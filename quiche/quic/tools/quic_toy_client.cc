// Copyright (c) 2012 The Chromium Authors. All rights reserved.
// Use of this source code is governed by a BSD-style license that can be
// found in the LICENSE file.

// A binary wrapper for QuicClient.
// Connects to a host using QUIC, sends a request to the provided URL, and
// displays the response.
//
// Some usage examples:
//
// Standard request/response:
//   quic_client www.google.com
//   quic_client www.google.com --quiet
//   quic_client www.google.com --port=443
//
// Use a specific version:
//   quic_client www.google.com --quic_version=23
//
// Send a POST instead of a GET:
//   quic_client www.google.com --body="this is a POST body"
//
// Append additional headers to the request:
//   quic_client www.google.com --headers="Header-A: 1234; Header-B: 5678"
//
// Connect to a host different to the URL being requested:
//   quic_client mail.google.com --host=www.google.com
//
// Connect to a specific IP:
//   IP=`dig www.google.com +short | head -1`
//   quic_client www.google.com --host=${IP}
//
// Send repeated requests and change ephemeral port between requests
//   quic_client www.google.com --num_requests=10
//
// Try to connect to a host which does not speak QUIC:
//   quic_client www.example.com
//
// This tool is available as a built binary at:
// /google/data/ro/teams/quic/tools/quic_client
// After submitting changes to this file, you will need to follow the
// instructions at go/quic_client_binary_update

#include "quiche/quic/tools/quic_toy_client.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <regex>
#include <map>
#include <algorithm>
#include <iomanip>

// recording
#include <fstream>
#include <sys/stat.h>

#include "absl/strings/escaping.h"
#include "absl/strings/str_split.h"
#include "absl/strings/string_view.h"
#include "quiche/quic/core/crypto/quic_client_session_cache.h"
#include "quiche/quic/core/quic_packets.h"
#include "quiche/quic/core/quic_server_id.h"
#include "quiche/quic/core/quic_utils.h"
#include "quiche/quic/core/quic_versions.h"
#include "quiche/quic/platform/api/quic_default_proof_providers.h"
#include "quiche/quic/platform/api/quic_ip_address.h"
#include "quiche/quic/platform/api/quic_socket_address.h"
#include "quiche/quic/tools/fake_proof_verifier.h"
#include "quiche/quic/tools/quic_simple_client_session.h"
#include "quiche/quic/tools/quic_url.h"
#include "quiche/common/http/http_header_block.h"
#include "quiche/common/platform/api/quiche_command_line_flags.h"
#include "quiche/common/platform/api/quiche_logging.h"
#include "quiche/common/quiche_text_utils.h"

namespace {

using quiche::QuicheTextUtils;

}  // namespace

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, host, "",
    "The IP or hostname to connect to. If not provided, the host "
    "will be derived from the provided URL.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, port, 0, "The port to connect to.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, ip_version_for_host_lookup, "",
                                "Only used if host address lookup is needed. "
                                "4=ipv4; 6=ipv6; otherwise=don't care.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, body, "",
                                "If set, send a POST with this body.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, body_hex, "",
    "If set, contents are converted from hex to ascii, before "
    "sending as body of a POST. e.g. --body_hex=\"68656c6c6f\"");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, headers, "",
    "A semicolon separated list of key:value pairs to "
    "add to request headers.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, quiet, false,
                                "Set to true for a quieter output experience.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, output_resolved_server_address, false,
    "Set to true to print the resolved IP of the server.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, quic_version, "",
    "QUIC version to speak, e.g. 21. If not set, then all available "
    "versions are offered in the handshake. Also supports wire versions "
    "such as Q043 or T099.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, connection_options, "",
    "Connection options as ASCII tags separated by commas, "
    "e.g. \"ABCD,EFGH\"");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, client_connection_options, "",
    "Client connection options as ASCII tags separated by commas, "
    "e.g. \"ABCD,EFGH\"");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, version_mismatch_ok, false,
    "If true, a version mismatch in the handshake is not considered a "
    "failure. Useful for probing a server to determine if it speaks "
    "any version of QUIC.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, force_version_negotiation, false,
    "If true, start by proposing a version that is reserved for version "
    "negotiation.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, multi_packet_chlo, false,
    "If true, add a transport parameter to make the ClientHello span two "
    "packets. Only works with QUIC+TLS.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, force_debugging_sni, "",
    "When non-empty, overrides the debugging_sni transport parameter.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, redirect_is_success, true,
    "If true, an HTTP response code of 3xx is considered to be a "
    "successful response, otherwise a failure.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, initial_mtu, 0,
                                "Initial MTU of the connection.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, num_requests, 1,
    "How many sequential requests to make on a single connection.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, ignore_errors, false,
                                "If true, ignore connection/response errors "
                                "and send all num_requests anyway.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, disable_certificate_verification, false,
    "If true, don't verify the server certificate.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, default_client_cert, "",
    "The path to the file containing PEM-encoded client default certificate to "
    "be sent to the server, if server requested client certs.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, default_client_cert_key, "",
    "The path to the file containing PEM-encoded private key of the client's "
    "default certificate for signing, if server requested client certs.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, drop_response_body, false,
    "If true, drop response body immediately after it is received.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    bool, disable_port_changes, false,
    "If true, do not change local port after each request.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(bool, one_connection_per_request, false,
                                "If true, close the connection after each "
                                "request. This allows testing 0-RTT.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, server_connection_id, "",
    "If non-empty, the client will use the given server connection id for all "
    "connections. The flag value is the hex-string of the on-wire connection id"
    " bytes, e.g. '--server_connection_id=0123456789abcdef'.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, server_connection_id_length, -1,
    "Length of the server connection ID used. This flag has no effects if "
    "--server_connection_id is non-empty.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, client_connection_id_length, -1,
                                "Length of the client connection ID used.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(int32_t, max_time_before_crypto_handshake_ms,
                                10000,
                                "Max time to wait before handshake completes.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    int32_t, max_inbound_header_list_size, 128 * 1024,
    "Max inbound header list size. 0 means default.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, interface_name, "",
                                "Interface name to bind QUIC UDP sockets to.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, alt_interface_name, "",
                                  "Alternative interface name to bind QUIC UDP sockets to for migration.");

DEFINE_QUICHE_COMMAND_LINE_FLAG(
    std::string, signing_algorithms_pref, "",
    "A textual specification of a set of signature algorithms that can be "
    "accepted by boring SSL SSL_set1_sigalgs_list()");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, save_html, "",
                                "If set, save HTML response to the specified file path (e.g., output.html or dir/file.html).");

DEFINE_QUICHE_COMMAND_LINE_FLAG(std::string, save_csv, "",
                                "If set, save scan results to the specified CSV file.");

namespace quic {
namespace {

// Script detection based on Unicode ranges
enum class Script {
  Latin,
  Greek,
  Cyrillic,
  Hebrew,
  Arabic,
  Devanagari,
  Thai,
  Hiragana,
  Katakana,
  Hangul,
  Han,
  Japanese,
  Unknown
};

const char* ScriptToString(Script script) {
  switch (script) {
    case Script::Latin: return "Latin";
    case Script::Greek: return "Greek";
    case Script::Cyrillic: return "Cyrillic";
    case Script::Hebrew: return "Hebrew";
    case Script::Arabic: return "Arabic";
    case Script::Devanagari: return "Devanagari";
    case Script::Thai: return "Thai";
    case Script::Hangul: return "Hangul";
    case Script::Han: return "Han";
    case Script::Japanese: return "Japanese";
    default: return "Unknown";
  }
}

Script DetectScript(uint32_t codepoint) {
  if (codepoint >= 0x0041 && codepoint <= 0x024F) return Script::Latin;
  if (codepoint >= 0x0370 && codepoint <= 0x03FF) return Script::Greek;
  if (codepoint >= 0x0400 && codepoint <= 0x052F) return Script::Cyrillic;
  if (codepoint >= 0x0590 && codepoint <= 0x05FF) return Script::Hebrew;
  if (codepoint >= 0x0600 && codepoint <= 0x06FF) return Script::Arabic;
  if (codepoint >= 0x0900 && codepoint <= 0x097F) return Script::Devanagari;
  if (codepoint >= 0x0E00 && codepoint <= 0x0E7F) return Script::Thai;
  if (codepoint >= 0x3040 && codepoint <= 0x309F || codepoint >= 0x30A0 && codepoint <= 0x30FF) return Script::Japanese;
  if (codepoint >= 0xAC00 && codepoint <= 0xD7AF) return Script::Hangul;
  if (codepoint >= 0x4E00 && codepoint <= 0x9FFF) return Script::Han;
  return Script::Unknown;
}

struct ScriptDetectionResult {
  std::string declared_language = "none";
  size_t text_length = 0;
  
  // Body text script analysis
  std::string body_primary_script = "Unknown";
  std::map<std::string, int> body_script_counts;
  int body_total_script_chars = 0;
  
  // HTML element counts (for geo-restriction comparison)
  std::map<std::string, int> html_element_counts;
  int total_html_elements = 0;
};

// Count HTML elements/tags in the HTML
std::map<std::string, int> CountHtmlElements(const std::string& html) {
  std::map<std::string, int> element_counts;
  size_t pos = 0;
  
  while (pos < html.length()) {
    // Find opening bracket
    size_t tag_start = html.find('<', pos);
    if (tag_start == std::string::npos) break;
    
    // Skip comments
    if (tag_start + 3 < html.length() && html.substr(tag_start, 4) == "<!--") {
      size_t comment_end = html.find("-->", tag_start + 4);
      pos = (comment_end != std::string::npos) ? comment_end + 3 : tag_start + 4;
      continue;
    }
    
    // Skip DOCTYPE
    if (tag_start + 8 < html.length() && 
        (html.substr(tag_start, 9) == "<!DOCTYPE" || html.substr(tag_start, 9) == "<!doctype")) {
      size_t doctype_end = html.find('>', tag_start + 9);
      pos = (doctype_end != std::string::npos) ? doctype_end + 1 : tag_start + 9;
      continue;
    }
    
    // Check for script or style tags and skip their entire content
    if (tag_start + 7 < html.length() && 
        (html.substr(tag_start, 7) == "<script" || html.substr(tag_start, 7) == "<SCRIPT")) {
      // Count the opening script tag
      size_t script_tag_end = html.find('>', tag_start);
      if (script_tag_end != std::string::npos) {
        element_counts["script"]++;
        // Skip to closing script tag
        size_t script_end = html.find("</script>", script_tag_end);
        if (script_end == std::string::npos) {
          script_end = html.find("</SCRIPT>", script_tag_end);
        }
        pos = (script_end != std::string::npos) ? script_end + 9 : script_tag_end + 1;
      } else {
        pos = tag_start + 7;
      }
      continue;
    }
    
    if (tag_start + 6 < html.length() && 
        (html.substr(tag_start, 6) == "<style" || html.substr(tag_start, 6) == "<STYLE")) {
      // Count the opening style tag
      size_t style_tag_end = html.find('>', tag_start);
      if (style_tag_end != std::string::npos) {
        element_counts["style"]++;
        // Skip to closing style tag
        size_t style_end = html.find("</style>", style_tag_end);
        if (style_end == std::string::npos) {
          style_end = html.find("</STYLE>", style_tag_end);
        }
        pos = (style_end != std::string::npos) ? style_end + 8 : style_tag_end + 1;
      } else {
        pos = tag_start + 6;
      }
      continue;
    }
    
    // Find closing bracket
    size_t tag_end = html.find('>', tag_start);
    if (tag_end == std::string::npos) break;
    
    // Extract tag content
    std::string tag_content = html.substr(tag_start + 1, tag_end - tag_start - 1);
    
    // Skip empty tags
    if (tag_content.empty()) {
      pos = tag_end + 1;
      continue;
    }
    
    // Check if it's a closing tag
    bool is_closing = (tag_content[0] == '/');
    if (is_closing) {
      tag_content = tag_content.substr(1);
    }
    
    // Extract tag name (first word)
    size_t space_pos = tag_content.find_first_of(" \t\n\r/");
    std::string tag_name = (space_pos != std::string::npos) 
                           ? tag_content.substr(0, space_pos) 
                           : tag_content;
    
    // Convert to lowercase
    std::transform(tag_name.begin(), tag_name.end(), tag_name.begin(), ::tolower);
    
    // Count the tag (skip closing tags for script/style as we already counted opening)
    if (!tag_name.empty() && !(is_closing && (tag_name == "script" || tag_name == "style"))) {
      element_counts[tag_name]++;
    }
    
    pos = tag_end + 1;
  }
  
  return element_counts;
}

// Extract text content from HTML body (strip tags)
std::string ExtractBodyText(const std::string& html) {
  std::string result;
  result.reserve(html.size() / 2);
  
  size_t pos = 0;
  
  while (pos < html.size()) {
    // Skip script tags completely
    if (pos + 7 < html.size() && 
        (html.substr(pos, 7) == "<script" || html.substr(pos, 7) == "<SCRIPT")) {
      size_t script_end = html.find("</script>", pos);
      if (script_end == std::string::npos) {
        script_end = html.find("</SCRIPT>", pos);
      }
      if (script_end != std::string::npos) {
        pos = script_end + 9;
      } else {
        pos += 7;
      }
      continue;
    }
    
    // Skip style tags completely
    if (pos + 6 < html.size() && 
        (html.substr(pos, 6) == "<style" || html.substr(pos, 6) == "<STYLE")) {
      size_t style_end = html.find("</style>", pos);
      if (style_end == std::string::npos) {
        style_end = html.find("</STYLE>", pos);
      }
      if (style_end != std::string::npos) {
        pos = style_end + 8;
      } else {
        pos += 6;
      }
      continue;
    }
    
    // Skip comments
    if (pos + 4 < html.size() && html.substr(pos, 4) == "<!--") {
      size_t comment_end = html.find("-->", pos + 4);
      if (comment_end != std::string::npos) {
        pos = comment_end + 3;
      } else {
        pos += 4;
      }
      continue;
    }
    
    // Find next tag
    size_t tag_start = html.find('<', pos);
    
    // Extract text before tag
    if (tag_start == std::string::npos) {
      // No more tags, add remaining text
      std::string text = html.substr(pos);
      // Filter out obvious JavaScript patterns
      if (text.find("function") == std::string::npos &&
          text.find("var ") == std::string::npos &&
          text.find("const ") == std::string::npos &&
          text.find("let ") == std::string::npos &&
          text.find("=>") == std::string::npos) {
        result += text;
      }
      break;
    }
    
    // Add text between tags (but filter JavaScript patterns)
    if (tag_start > pos) {
      std::string text = html.substr(pos, tag_start - pos);
      // Skip text that looks like JavaScript
      if (text.find("function") == std::string::npos &&
          text.find("var ") == std::string::npos &&
          text.find("const ") == std::string::npos &&
          text.find("let ") == std::string::npos &&
          text.find("return ") == std::string::npos &&
          text.find("=>") == std::string::npos &&
          text.find("window.") == std::string::npos &&
          text.find("document.") == std::string::npos &&
          !(text.find('(') != std::string::npos && text.find(')') != std::string::npos && text.find('{') != std::string::npos)) {
        result += text;
        result += ' ';
      }
    }
    
    // Skip the tag itself
    size_t tag_end = html.find('>', tag_start);
    if (tag_end == std::string::npos) {
      break;
    }
    pos = tag_end + 1;
  }
  
  return result;
}

// Decode UTF-8 character to get codepoint
uint32_t DecodeUtf8Char(const std::string& str, size_t& pos) {
  if (pos >= str.length()) return 0;
  
  unsigned char c = str[pos];
  uint32_t codepoint = 0;
  int bytes = 0;
  
  if ((c & 0x80) == 0) {
    // 1-byte (ASCII)
    codepoint = c;
    bytes = 1;
  } else if ((c & 0xE0) == 0xC0) {
    // 2-byte
    codepoint = c & 0x1F;
    bytes = 2;
  } else if ((c & 0xF0) == 0xE0) {
    // 3-byte
    codepoint = c & 0x0F;
    bytes = 3;
  } else if ((c & 0xF8) == 0xF0) {
    // 4-byte
    codepoint = c & 0x07;
    bytes = 4;
  } else {
    pos++;
    return 0; // Invalid UTF-8
  }
  
  // Read continuation bytes
  for (int i = 1; i < bytes && (pos + i) < str.length(); i++) {
    unsigned char cont = str[pos + i];
    if ((cont & 0xC0) != 0x80) {
      pos++;
      return 0; // Invalid UTF-8
    }
    codepoint = (codepoint << 6) | (cont & 0x3F);
  }
  
  pos += bytes;
  return codepoint;
}

// Detect scripts in response body
ScriptDetectionResult DetectScripts(const std::string& response_headers, const std::string& response_body) {
  ScriptDetectionResult result;
  
  // Extract HTML lang attribute
  std::regex html_lang_regex(R"(<html[^>]+lang\s*=\s*[\"']([^\"']+)[\"'])", std::regex_constants::icase);
  std::smatch html_match;
  if (std::regex_search(response_body, html_match, html_lang_regex)) {
    result.declared_language = html_match[1].str();
  }
  
  // Extract meta Content-Language
  std::regex meta_lang_regex(R"(<meta[^>]+http-equiv\s*=\s*[\"']content-language[\"'][^>]+content\s*=\s*[\"']([^\"']+)[\"'])", std::regex_constants::icase);
  std::smatch meta_match;
  if (result.declared_language == "none" && std::regex_search(response_body, meta_match, meta_lang_regex)) {
    result.declared_language = meta_match[1].str();
  }
  
  result.text_length = response_body.length();
  
  if (result.text_length < 50) {
    return result;
  }
  
  // 1. Count HTML elements (for geo-restriction comparison)
  result.html_element_counts = CountHtmlElements(response_body);
  for (const auto& [tag, count] : result.html_element_counts) {
    result.total_html_elements += count;
  }
  
  // 2. Count scripts in BODY TEXT only (visible content)
  std::string body_text = ExtractBodyText(response_body);
  size_t pos = 0;
  while (pos < body_text.length()) {
    uint32_t codepoint = DecodeUtf8Char(body_text, pos);
    if (codepoint == 0) continue;
    
    Script script = DetectScript(codepoint);
    if (script != Script::Unknown) {
      std::string script_name = ScriptToString(script);
      result.body_script_counts[script_name]++;
      result.body_total_script_chars++;
    }
  }
  
  // Find the most common script in body text
  if (!result.body_script_counts.empty()) {
    auto max_elem = std::max_element(result.body_script_counts.begin(), result.body_script_counts.end(),
      [](const auto& a, const auto& b) { return a.second < b.second; });
    result.body_primary_script = max_elem->first;
  }
  
  return result;
}

// Save scan results to CSV file
void AppendScanResultToCsv(const std::string& csv_filename,
                           const std::string& domain,
                           const std::string& ip,
                           const std::string& redirected_domain,
                           const std::string& redirect_ip,
                           int status,
                           const std::string& declared_lang,
                           const std::string& detected_unicode,
                           size_t html_size,
                           int64_t total_time_ms,
                           const std::map<std::string, int>& element_counts) {
  // Check if file exists and is empty
  struct stat st;
  bool write_header = (stat(csv_filename.c_str(), &st) != 0) || (st.st_size == 0);

  std::ofstream csv_file(csv_filename, std::ios::app);
  if (!csv_file.is_open()) {
    std::cerr << "Failed to open CSV file: " << csv_filename << std::endl;
    return;
  }

  if (write_header) {
    csv_file << "domain,ip,redirected_domain,redirect_ip,status,declared_lang,detected_unicode,html_size,total_time_ms,frequency_vector\n";
  }

  // Build frequency vector (e.g., "div:2|style:343|svg:343")
  std::string frequency_vector;
  if (!element_counts.empty()) {
    std::vector<std::pair<std::string, int>> sorted_elements(element_counts.begin(), element_counts.end());
    std::sort(sorted_elements.begin(), sorted_elements.end(),
      [](const auto& a, const auto& b) { return a.second > b.second; });
    
    for (size_t i = 0; i < sorted_elements.size(); ++i) {
      if (i > 0) frequency_vector += "|";
      frequency_vector += sorted_elements[i].first + ":" + std::to_string(sorted_elements[i].second);
    }
  }

  // Escape helper for CSV fields
  auto escape_csv = [](const std::string& s) {
    if (s.find(',') != std::string::npos || s.find('"') != std::string::npos || s.find('\n') != std::string::npos) {
      std::string escaped = "\"";
      for (char c : s) {
        if (c == '"') escaped += "\"\"";
        else escaped += c;
      }
      escaped += "\"";
      return escaped;
    }
    return s;
  };

  csv_file << escape_csv(domain) << ","
           << escape_csv(ip) << ","
           << escape_csv(redirected_domain) << ","
           << escape_csv(redirect_ip) << ","
           << status << ","
           << escape_csv(declared_lang) << ","
           << escape_csv(detected_unicode) << ","
           << html_size << ","
           << total_time_ms << ","
           << escape_csv(frequency_vector) << "\n";
  
  csv_file.close();
  std::cout << "Saved scan result to CSV: " << csv_filename << std::endl;
}

// Append error entry to CSV (for connection/request failures)
void AppendErrorToCsv(const std::string& csv_filename,
                      const std::string& domain,
                      const std::string& error_message) {
  // Check if file exists and is empty
  struct stat st;
  bool write_header = (stat(csv_filename.c_str(), &st) != 0) || (st.st_size == 0);

  std::ofstream csv_file(csv_filename, std::ios::app);
  if (!csv_file.is_open()) {
    std::cerr << "Failed to open CSV file: " << csv_filename << std::endl;
    return;
  }

  if (write_header) {
    csv_file << "domain,ip,redirected_domain,redirect_ip,status,declared_lang,detected_unicode,html_size,total_time_ms,frequency_vector\n";
  }

  // Escape helper for CSV fields
  auto escape_csv = [](const std::string& s) {
    if (s.find(',') != std::string::npos || s.find('"') != std::string::npos || s.find('\n') != std::string::npos) {
      std::string escaped = "\"";
      for (char c : s) {
        if (c == '"') escaped += "\"\"";
        else escaped += c;
      }
      escaped += "\"";
      return escaped;
    }
    return s;
  };

  // Write row with domain and error message as status, other fields empty
  csv_file << escape_csv(domain) << ","
           << ","  // ip
           << ","  // redirected_domain
           << ","  // redirect_ip
           << escape_csv(error_message) << ","  // status (error message)
           << ","  // declared_lang
           << ","  // detected_unicode
           << "0,"  // html_size
           << "0,"  // total_time_ms
           << "" << "\n";  // frequency_vector
  
  csv_file.close();
}

// Save HTML response to file
void SaveHtmlToFile(const std::string& user_filename, const std::string& html_content,
                    int request_number = 0, int total_requests = 1) {
  // Extract directory path and create it if needed
  std::string filename = user_filename;
  size_t last_slash = filename.find_last_of("/\\");
  if (last_slash != std::string::npos) {
    std::string dir_path = filename.substr(0, last_slash);
    // Create directory recursively using system command
    std::string mkdir_cmd = "mkdir -p \"" + dir_path + "\" 2>/dev/null";
    system(mkdir_cmd.c_str());
  }
  
  // Add numbering if there are multiple requests
  // Insert the number before the file extension
  if (total_requests > 1 && request_number > 0) {
    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos != std::string::npos && dot_pos > last_slash) {
      // Insert "_N" before the extension
      filename = filename.substr(0, dot_pos) + "_" + std::to_string(request_number) + filename.substr(dot_pos);
    } else {
      // No extension, just append "_N"
      filename += "_" + std::to_string(request_number);
    }
  }
  
  std::ofstream html_file(filename, std::ios::binary);
  if (html_file.is_open()) {
    html_file << html_content;
    html_file.close();
    std::cout << "Saved HTML to: " << filename << " (" << html_content.size() << " bytes)" << std::endl;
  } else {
    std::cerr << "Failed to save HTML to: " << filename << std::endl;
  }
}

// Record a log entry in CSV format.
void AppendCsvLog(const std::string& log_filename,
                  const std::string& host,
                  const std::string& server_ip,
                  bool migration_disabled,
                  size_t response_size,
                  int64_t ttlb_ms) {
  // Check if file exists and is empty
  struct stat st;
  bool write_header = (stat(log_filename.c_str(), &st) != 0) || (st.st_size == 0);

  std::ofstream log_file(log_filename, std::ios::app);
  if (log_file.is_open()) {
    if (write_header) {
      log_file << "host,server_ip,disable_conn_migration,response_size,ttlb_ms\n";
    }
    log_file << '"' << host << "\","
             << '"' << server_ip << "\","
             << (migration_disabled ? "1" : "0") << ","
             << response_size << ","
             << ttlb_ms
             << "\n";
  }
}

// Creates a ClientProofSource which only contains a default client certificate.
// Return nullptr for failure.
std::unique_ptr<ClientProofSource> CreateTestClientProofSource(
    absl::string_view default_client_cert_file,
    absl::string_view default_client_cert_key_file) {
  std::ifstream cert_stream(std::string{default_client_cert_file},
                            std::ios::binary);
  std::vector<std::string> certs =
      CertificateView::LoadPemFromStream(&cert_stream);
  if (certs.empty()) {
    std::cerr << "Failed to load client certs." << std::endl;
    return nullptr;
  }

  std::ifstream key_stream(std::string{default_client_cert_key_file},
                           std::ios::binary);
  std::unique_ptr<CertificatePrivateKey> private_key =
      CertificatePrivateKey::LoadPemFromStream(&key_stream);
  if (private_key == nullptr) {
    std::cerr << "Failed to load client cert key." << std::endl;
    return nullptr;
  }

  auto proof_source = std::make_unique<DefaultClientProofSource>();
  if (!proof_source->AddCertAndKey(
          {"*"},
          quiche::QuicheReferenceCountedPointer<ClientProofSource::Chain>(
              new ClientProofSource::Chain(certs)),
          std::move(*private_key))) {
    std::cerr << "Failed to add client cert and key." << std::endl;
    return nullptr;
  }

  return proof_source;
}

// Structure to hold response data for unified processing
struct ResponseResult {
  std::string domain;
  std::string original_ip;
  std::string redirected_domain;
  std::string redirect_ip;
  int status_code = 0;
  std::string response_body;
  std::string response_headers;
  QuicTime::Delta ttfb = QuicTime::Delta::Zero();
  QuicTime::Delta ttlb = QuicTime::Delta::Zero();
};

// Display analysis output for a response (scripts, elements, etc.)
void DisplayAnalysis(const ResponseResult& result, const std::string& host,
                     bool migration_disabled) {
  // Script detection
  ScriptDetectionResult script_result = DetectScripts(
      result.response_headers, result.response_body);
  
  if (!script_result.html_element_counts.empty()) {
    std::vector<std::pair<std::string, int>> sorted_elements;
    for (const auto& [tag, count] : script_result.html_element_counts) {
      sorted_elements.push_back({tag, count});
    }
    std::sort(sorted_elements.begin(), sorted_elements.end(),
      [](const auto& a, const auto& b) { return a.second > b.second; });
  }
  
  // Extract and show sample of body text for debugging
  std::string body_text = ExtractBodyText(result.response_body);
  
  // Show script distribution for body text
  if (!script_result.body_script_counts.empty()) {
    std::vector<std::pair<std::string, int>> sorted_body_scripts;
    for (const auto& [script, count] : script_result.body_script_counts) {
      sorted_body_scripts.push_back({script, count});
    }
    std::sort(sorted_body_scripts.begin(), sorted_body_scripts.end(),
      [](const auto& a, const auto& b) { return a.second > b.second; });
  }

  AppendCsvLog("quic_client_log.csv", host, result.original_ip,
               migration_disabled, 
               result.response_body.size(), result.ttlb.ToMilliseconds());

  std::cout << "Body Size: " << result.response_body.size() << std::endl;
  std::cout << "Request completed with TTFB(ms): " << result.ttfb.ToMilliseconds() 
            << ", TTLB(ms): " << result.ttlb.ToMilliseconds() << '\n';
  
  QUIC_LOG(INFO) << "Request completed with TTFB(us): " << result.ttfb.ToMicroseconds() 
                 << ", TTLB(us): " << result.ttlb.ToMicroseconds();
}

// Display error response analysis (shows HTML element counts)
void DisplayErrorAnalysis(const ResponseResult& result) {
  if (result.response_body.size() == 0) {
    return;
  }

  // Count HTML elements
  ScriptDetectionResult script_result = DetectScripts(
      result.response_headers, result.response_body);
  
  std::cout << "\n=== HTML Element Counts ===" << std::endl;
  std::cout << "Total HTML Elements: " << script_result.total_html_elements << std::endl;
  if (!script_result.html_element_counts.empty()) {
    std::vector<std::pair<std::string, int>> sorted_elements;
    for (const auto& [tag, count] : script_result.html_element_counts) {
      sorted_elements.push_back({tag, count});
    }
    std::sort(sorted_elements.begin(), sorted_elements.end(),
      [](const auto& a, const auto& b) { return a.second > b.second; });
    
    // Show top 20 most common elements
    int shown = 0;
    for (const auto& [tag, count] : sorted_elements) {
      if (shown++ >= 20) break;
      std::cout << "  <" << tag << ">: " << count << std::endl;
    }
  }
  std::cout << "===========================\n" << std::endl;
  
  std::cout << "total received bytes: " << result.response_body.size() << std::endl;
}

// Process and save error response (for failed requests)
void ProcessAndSaveErrorResponse(const ResponseResult& result, bool is_quiet,
                                int request_number = 0,
                                int total_requests = 1) {
  // Always save HTML if flag is set and response body exists (independent of quiet mode)
  if (result.response_body.size() > 0) {
    std::string html_filename = quiche::GetQuicheCommandLineFlag(FLAGS_save_html);
    if (!html_filename.empty()) {
      SaveHtmlToFile(html_filename, result.response_body, request_number, total_requests);
    }
  }
  
  // Display error analysis if not quiet
  if (!is_quiet) {
    DisplayErrorAnalysis(result);
  }
  
  // Always save CSV if flag is set and response body exists (independent of quiet mode)
  if (result.response_body.size() > 0) {
    std::string csv_filename = quiche::GetQuicheCommandLineFlag(FLAGS_save_csv);
    if (!csv_filename.empty()) {
      ScriptDetectionResult script_result = DetectScripts(
          result.response_headers, result.response_body);
      AppendScanResultToCsv(csv_filename, result.domain, result.original_ip,
                            result.redirected_domain, result.redirect_ip,
                            result.status_code, script_result.declared_language,
                            script_result.body_primary_script, result.response_body.size(),
                            result.ttlb.ToMilliseconds(),
                            script_result.html_element_counts);
    }
  }
}

// Unified response processing: save HTML, save CSV, display analysis
void ProcessAndSaveResponse(const ResponseResult& result, 
                            QuicSpdyClientBase* client,
                            const std::string& host,
                            bool is_quiet,
                            int request_number = 0,
                            int total_requests = 1) {
  // Always save HTML if flag is set (independent of quiet mode)
  std::string html_filename = quiche::GetQuicheCommandLineFlag(FLAGS_save_html);
  if (!html_filename.empty()) {
    SaveHtmlToFile(html_filename, result.response_body, request_number, total_requests);
  }
  
  // Always save CSV if flag is set (independent of quiet mode)
  std::string csv_filename = quiche::GetQuicheCommandLineFlag(FLAGS_save_csv);
  if (!csv_filename.empty()) {
    ScriptDetectionResult script_result = DetectScripts(
        result.response_headers, result.response_body);
    AppendScanResultToCsv(csv_filename, result.domain, result.original_ip,
                          result.redirected_domain, result.redirect_ip,
                          result.status_code, script_result.declared_language,
                          script_result.body_primary_script, result.response_body.size(),
                          result.ttlb.ToMilliseconds(),
                          script_result.html_element_counts);
  }
  
  // Display analysis if not quiet
  if (!is_quiet) {
    DisplayAnalysis(result, host, client->session()->IsDisableConnectionMigration());
  }
}

}  // namespace

QuicToyClient::QuicToyClient(ClientFactory* client_factory)
    : client_factory_(client_factory) {}





int QuicToyClient::SendRequestsAndPrintResponses(
    std::vector<std::string> urls) {
  QuicUrl url(urls[0], "https");
  std::string host = quiche::GetQuicheCommandLineFlag(FLAGS_host);
  if (host.empty()) {
    host = url.host();
  }
  int port = quiche::GetQuicheCommandLineFlag(FLAGS_port);
  if (port == 0) 
  {
    port = url.port();
  }

  quic::ParsedQuicVersionVector versions = quic::CurrentSupportedVersions();

  std::string quic_version_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_quic_version);
  if (!quic_version_string.empty()) {
    versions = quic::ParseQuicVersionVectorString(quic_version_string);
  }

  if (versions.empty()) {
    std::cerr << "No known version selected." << std::endl;
    return 1;
  }

  for (const quic::ParsedQuicVersion& version : versions) {
    quic::QuicEnableVersion(version);
  }

  if (quiche::GetQuicheCommandLineFlag(FLAGS_force_version_negotiation)) {
    versions.insert(versions.begin(),
                    quic::QuicVersionReservedForNegotiation());
  }

  const int32_t num_requests(
      quiche::GetQuicheCommandLineFlag(FLAGS_num_requests));
  std::unique_ptr<quic::ProofVerifier> proof_verifier;
  if (quiche::GetQuicheCommandLineFlag(
          FLAGS_disable_certificate_verification)) {
    proof_verifier = std::make_unique<FakeProofVerifier>();
  } else {
    proof_verifier = quic::CreateDefaultProofVerifier(url.host());
  }
  std::unique_ptr<quic::SessionCache> session_cache;
  if (num_requests > 1 &&
      quiche::GetQuicheCommandLineFlag(FLAGS_one_connection_per_request)) {
    session_cache = std::make_unique<QuicClientSessionCache>();
  }

  QuicConfig config;
  std::string connection_options_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_connection_options);
  if (!connection_options_string.empty()) {
    config.SetConnectionOptionsToSend(
        ParseQuicTagVector(connection_options_string));
  }
  std::string client_connection_options_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_client_connection_options);
  if (!client_connection_options_string.empty()) {
    config.SetClientConnectionOptions(
        ParseQuicTagVector(client_connection_options_string));
  }
  if (quiche::GetQuicheCommandLineFlag(FLAGS_multi_packet_chlo)) {
    // Make the ClientHello span multiple packets by adding a large 'discard'
    // transport parameter.
    config.SetDiscardLengthToSend(2000);
  }
  std::string force_debugging_sni =
      quiche::GetQuicheCommandLineFlag(FLAGS_force_debugging_sni);
  if (!force_debugging_sni.empty()) {
    config.SetDebuggingSniToSend(force_debugging_sni);
  }
  config.set_max_time_before_crypto_handshake(
      QuicTime::Delta::FromMilliseconds(quiche::GetQuicheCommandLineFlag(
          FLAGS_max_time_before_crypto_handshake_ms)));

  int address_family_for_lookup = AF_UNSPEC;
  if (quiche::GetQuicheCommandLineFlag(FLAGS_ip_version_for_host_lookup) ==
      "4") {
    address_family_for_lookup = AF_INET;
  } else if (quiche::GetQuicheCommandLineFlag(
                 FLAGS_ip_version_for_host_lookup) == "6") {
    address_family_for_lookup = AF_INET6;
  }

  // Build the client, and try to connect.
  std::unique_ptr<QuicSpdyClientBase> client = client_factory_->CreateClient(
      url.host(), host, address_family_for_lookup, port, versions, config,
      std::move(proof_verifier), std::move(session_cache));

  if (client == nullptr) {
    std::cerr << "Failed to create client." << std::endl;
    return 1;
  }

  if (!quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert).empty() &&
      !quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert_key)
           .empty()) {
    std::unique_ptr<ClientProofSource> proof_source =
        CreateTestClientProofSource(
            quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert),
            quiche::GetQuicheCommandLineFlag(FLAGS_default_client_cert_key));
    if (proof_source == nullptr) {
      std::cerr << "Failed to create client proof source." << std::endl;
      return 1;
    }
    client->crypto_config()->set_proof_source(std::move(proof_source));
  }

  int32_t initial_mtu = quiche::GetQuicheCommandLineFlag(FLAGS_initial_mtu);
  client->set_initial_max_packet_length(
      initial_mtu != 0 ? initial_mtu : quic::kDefaultMaxPacketSize);
  client->set_drop_response_body(
      quiche::GetQuicheCommandLineFlag(FLAGS_drop_response_body));
  const std::string server_connection_id_hex_string =
      quiche::GetQuicheCommandLineFlag(FLAGS_server_connection_id);
  QUICHE_CHECK(server_connection_id_hex_string.size() % 2 == 0)
      << "The length of --server_connection_id must be even. It is "
      << server_connection_id_hex_string.size() << "-byte long.";
  if (!server_connection_id_hex_string.empty()) {
    std::string server_connection_id_bytes;
    QUICHE_CHECK(absl::HexStringToBytes(server_connection_id_hex_string,
                                        &server_connection_id_bytes))
        << "Failed to parse --server_connection_id hex string.";
    client->set_server_connection_id_override(QuicConnectionId(
        server_connection_id_bytes.data(), server_connection_id_bytes.size()));
  }
  const int32_t server_connection_id_length =
      quiche::GetQuicheCommandLineFlag(FLAGS_server_connection_id_length);
  if (server_connection_id_length >= 0) {
    client->set_server_connection_id_length(server_connection_id_length);
  }
  const int32_t client_connection_id_length =
      quiche::GetQuicheCommandLineFlag(FLAGS_client_connection_id_length);
  if (client_connection_id_length >= 0) {
    client->set_client_connection_id_length(client_connection_id_length);
  }
  const size_t max_inbound_header_list_size =
      quiche::GetQuicheCommandLineFlag(FLAGS_max_inbound_header_list_size);
  if (max_inbound_header_list_size > 0) {
    client->set_max_inbound_header_list_size(max_inbound_header_list_size);
  }
  const std::string interface_name =
      quiche::GetQuicheCommandLineFlag(FLAGS_interface_name);
  if (!interface_name.empty()) {
    client->set_interface_name(interface_name);
  }
  const std::string alt_interface_name = 
      quiche::GetQuicheCommandLineFlag(FLAGS_alt_interface_name);
  if (!alt_interface_name.empty()) { 
    client->set_alt_interface_name(alt_interface_name);
  }

  const std::string signing_algorithms_pref =
      quiche::GetQuicheCommandLineFlag(FLAGS_signing_algorithms_pref);
  if (!signing_algorithms_pref.empty()) {
    client->SetTlsSignatureAlgorithms(signing_algorithms_pref);
  }
  if (!client->Initialize()) {
    std::cerr << "Failed to initialize client." << std::endl;
    return 1;
  }
  if (!client->Connect()) {
    quic::QuicErrorCode error = client->session()->error();
    if (error == quic::QUIC_INVALID_VERSION) {
      std::cerr << "Failed to negotiate version with " << host << ":" << port
                << "(" << client->server_address().host() << ":" << client->server_address().port() << ")"
                << ". " << client->session()->error_details() << std::endl;
      // 0: No error.
      // 20: Failed to connect due to QUIC_INVALID_VERSION.
      return quiche::GetQuicheCommandLineFlag(FLAGS_version_mismatch_ok) ? 0
                                                                         : 20;
    }
    std::string error_code = quic::QuicErrorCodeToString(error);
    std::string error_msg = error_code + " " + client->session()->error_details();
    std::cerr << "Failed to connect to " << host << ":" << port 
              << "(" << client->server_address().host() << ":" << client->server_address().port() << ")"
              << ". " << error_msg << std::endl;
    
    // Log error to CSV if enabled (only error code, not details)
    std::string csv_filename = quiche::GetQuicheCommandLineFlag(FLAGS_save_csv);
    if (!csv_filename.empty()) {
      AppendErrorToCsv(csv_filename, host, error_code);
    }
    
    return 1;
  }

  std::cout << "Connected to " << host << "("<< client->server_address().host() << ":" << port << 
   ") - Disable connection migration: " << client->session()->IsDisableConnectionMigration();
  if (quiche::GetQuicheCommandLineFlag(FLAGS_output_resolved_server_address)) {
    std::cout << ", resolved IP " << client->server_address().host().ToString();
  }
  std::cout << std::endl;
  
  // Set up interim headers callback to handle HTTP 103 Early Hints
  auto* session = static_cast<QuicSimpleClientSession*>(client->session());
  session->set_on_interim_headers(
      [](const quiche::HttpHeaderBlock& headers) {
        // Handle interim/preliminary headers (e.g., HTTP 103 Early Hints)
        // Just acknowledge them without special processing
      });
  
  // Construct the string body from flags, if provided.
  std::string body = quiche::GetQuicheCommandLineFlag(FLAGS_body);
  if (!quiche::GetQuicheCommandLineFlag(FLAGS_body_hex).empty()) {
    QUICHE_DCHECK(quiche::GetQuicheCommandLineFlag(FLAGS_body).empty())
        << "Only set one of --body and --body_hex.";
    const bool success = absl::HexStringToBytes(
        quiche::GetQuicheCommandLineFlag(FLAGS_body_hex), &body);
    QUICHE_DCHECK(success) << "Failed to parse --body_hex.";
  }

  // Construct a GET or POST request for supplied URL.
  quiche::HttpHeaderBlock header_block;
  header_block[":method"] = body.empty() ? "GET" : "POST";
  header_block[":scheme"] = url.scheme();
  header_block[":authority"] = url.HostPort();
  header_block[":path"] = url.PathParamsQuery();

  // [SD] Pretend real browser
  header_block["user-agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
  header_block["accept"] = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8";
  // header_block["accept-language"] = "en-US,en;q=0.9";
  // header_block["accept-encoding"] = "gzip, deflate, br";
  header_block["accept-encoding"] = "identity";
  header_block["upgrade-insecure-requests"] = "1";
  header_block["sec-fetch-site"] = "none";
  header_block["sec-fetch-mode"] = "navigate";
  header_block["sec-fetch-user"] = "?1";
  header_block["sec-fetch-dest"] = "document";


  // Append any additional headers supplied on the command line.
  const std::string headers = quiche::GetQuicheCommandLineFlag(FLAGS_headers);
  for (absl::string_view sp : absl::StrSplit(headers, ';')) {
    QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&sp);
    if (sp.empty()) {
      continue;
    }
    std::vector<absl::string_view> kv =
        absl::StrSplit(sp, absl::MaxSplits(':', 1));
    QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[0]);
    QuicheTextUtils::RemoveLeadingAndTrailingWhitespace(&kv[1]);
    header_block[kv[0]] = kv[1];
  }

  // Make sure to store the response, for later output.
  client->set_store_response(true);

  // [SD] Test
  client->WaitForHandshakeConfirmed();
  
  for (int i = 0; i < num_requests; ++i) {
    // Print request details before sending.
    if (!quiche::GetQuicheCommandLineFlag(FLAGS_quiet)) {
      std::cout << "Request:" << std::endl;
      std::cout << "headers:" << header_block.DebugString();
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_body_hex).empty()) {
        // Print the user provided hex, rather than binary body.
        std::cout << "body:\n" << QuicheTextUtils::HexDump(body) << std::endl;
      } else {
        std::cout << "body: " << body << std::endl;
      }
      std::cout << std::endl;
    }
    
    // Send the request.
    client->SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);
    
    // Print response details.
    if (!quiche::GetQuicheCommandLineFlag(FLAGS_quiet)) {

      if (!client->preliminary_response_headers().empty()) {
        std::cout << "Preliminary response headers: "
                  << client->preliminary_response_headers() << std::endl;
        std::cout << std::endl;
      }

      std::cout << "Response:" << std::endl;
      std::cout << "headers: " << client->latest_response_headers()
                << std::endl;

    }

    if (!client->connected()) {
      std::string error_code = quic::QuicErrorCodeToString(client->session()->error());
      std::string error_msg = error_code + " " + client->session()->error_details();
      std::cerr << "Request caused connection failure. Error: " << error_msg << std::endl;
      
      // Log error to CSV if enabled (only error code, not details)
      std::string csv_filename = quiche::GetQuicheCommandLineFlag(FLAGS_save_csv);
      if (!csv_filename.empty()) {
        AppendErrorToCsv(csv_filename, host, error_code);
      }
      
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
        return 1;
      }
    }

    int response_code = client->latest_response_code();
    if (response_code >= 200 && response_code < 300) {
      std::cout << "Request succeeded (" << response_code << ")." << std::endl;
      
      ResponseResult result;
      result.domain = host;
      result.original_ip = client->server_address().host().ToString();
      result.redirected_domain = "";
      result.redirect_ip = "";
      result.status_code = response_code;
      result.response_body = client->latest_response_body();
      result.response_headers = client->latest_response_headers();
      result.ttfb = client->latest_ttfb();
      result.ttlb = client->latest_ttlb();
      
      ProcessAndSaveResponse(result, client.get(), host, 
                            quiche::GetQuicheCommandLineFlag(FLAGS_quiet),
                            i + 1, num_requests);
    } else if (response_code >= 300 && response_code < 400) {
      // Handle redirects (301, 302, etc.) with loop for redirect chains
      int redirect_count = 0;
      const int max_redirects = 10; // Prevent infinite redirect loops
      std::string current_host = host; // Track current connected host
      std::string original_ip = client->server_address().host().ToString(); // Track original IP
      
      while (response_code >= 300 && response_code < 400 && redirect_count < max_redirects) {
        redirect_count++;
        try {
          const auto& response_header_block = client->latest_response_header_block();
          auto location_it = response_header_block.find("location");
          
          if (location_it != response_header_block.end()) {
            std::string location = std::string(location_it->second);
            std::cout << "Redirect #" << redirect_count << " (" << response_code << ") to: " << location << std::endl;
            
            // Handle relative URLs
            if (location.length() > 0 && location[0] == '/') {
              // Relative URL - use current scheme and authority  
              auto scheme_it = header_block.find(":scheme");
              auto authority_it = header_block.find(":authority");
              if (scheme_it != header_block.end() && authority_it != header_block.end()) {
                std::string current_scheme = std::string(scheme_it->second);
                std::string current_authority = std::string(authority_it->second);
                location = current_scheme + "://" + current_authority + location;
                std::cout << "Relative URL converted to: " << location << std::endl;
              }
            }
            
            // Parse the new URL
            QuicUrl redirect_url(location, "https");
            
            // Clean up double slashes in path
            std::string clean_path = redirect_url.PathParamsQuery();
            if (clean_path.length() >= 2 && clean_path.substr(0, 2) == "//") {
              clean_path = clean_path.substr(1); // Remove one slash
            }
            
            // Check if hostname changed - need to reconnect if so
            if (redirect_url.host() != current_host) {
              // Disconnect from old server
              client->Disconnect();
              
              // Create new proof verifier for new hostname
              std::unique_ptr<quic::ProofVerifier> new_proof_verifier;
              if (quiche::GetQuicheCommandLineFlag(FLAGS_disable_certificate_verification)) {
                new_proof_verifier = std::make_unique<FakeProofVerifier>();
              } else {
                new_proof_verifier = quic::CreateDefaultProofVerifier(redirect_url.host());
              }
              
              // Get redirect port
              int redirect_port = redirect_url.port();
              if (redirect_port == 0) {
                redirect_port = 443; // Default HTTPS port
              }
              
              // Create new client for the new hostname
              client = client_factory_->CreateClient(
                  redirect_url.host(), redirect_url.host(), address_family_for_lookup,
                  redirect_port, versions, config, std::move(new_proof_verifier), nullptr);
              
              if (client == nullptr) {
                std::cerr << "Failed to create client for redirected host." << std::endl;
                break;
              }
              
              // Apply same settings as original client
              client->set_initial_max_packet_length(
                  initial_mtu != 0 ? initial_mtu : quic::kDefaultMaxPacketSize);
              client->set_drop_response_body(
                  quiche::GetQuicheCommandLineFlag(FLAGS_drop_response_body));
              if (max_inbound_header_list_size > 0) {
                client->set_max_inbound_header_list_size(max_inbound_header_list_size);
              }
              if (!interface_name.empty()) {
                client->set_interface_name(interface_name);
              }
              if (!alt_interface_name.empty()) {
                client->set_alt_interface_name(alt_interface_name);
              }
              client->set_store_response(true);
              
              // Initialize and connect to new server
              if (!client->Initialize()) {
                std::cerr << "Failed to initialize client for redirected host." << std::endl;
                break;
              }
              
              if (!client->Connect()) {
                quic::QuicErrorCode error = client->session()->error();
                std::cerr << "Failed to connect to redirected host " << redirect_url.host() 
                          << ":" << redirect_port << ". " 
                          << quic::QuicErrorCodeToString(error) << " "
                          << client->session()->error_details() << std::endl;
                break;
              }
              
              // Set up interim headers callback for redirected host
              auto* session = static_cast<QuicSimpleClientSession*>(client->session());
              session->set_on_interim_headers(
                  [](const quiche::HttpHeaderBlock& headers) {
                    // Handle interim/preliminary headers (e.g., HTTP 103 Early Hints)
                    // Just acknowledge them without special processing
                  });
              
              // Wait for handshake
              client->WaitForHandshakeConfirmed();
              
              // Update current_host
              current_host = redirect_url.host();
            }
            
            // Update header block with new URL
            header_block[":scheme"] = redirect_url.scheme();
            header_block[":authority"] = redirect_url.HostPort();
            header_block[":path"] = clean_path;
            
            client->SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);
            
            // Update response_code for the next iteration
            response_code = client->latest_response_code();
          } else {
            std::cout << "Redirect response missing Location header." << std::endl;
            break; // Exit redirect loop if no location header
          }
        } catch (const std::exception& e) {
          std::cout << "Error handling redirect: " << e.what() << std::endl;
          break; // Exit redirect loop on error
        }
      }
      
      // Check final result after all redirects
      if (redirect_count >= max_redirects) {
        std::cout << "Too many redirects (" << max_redirects << "). Stopping." << std::endl;
      } else if (response_code >= 200 && response_code < 300) {
        std::cout << "Redirect chain followed successfully. Final response (" << response_code << ") after " << redirect_count << " redirects." << std::endl;
        
        ResponseResult result;
        result.domain = host;
        result.original_ip = original_ip;
        result.redirected_domain = current_host;
        result.redirect_ip = client->server_address().host().ToString();
        result.status_code = response_code;
        result.response_body = client->latest_response_body();
        result.response_headers = client->latest_response_headers();
        result.ttfb = client->latest_ttfb();
        result.ttlb = client->latest_ttlb();
        
        ProcessAndSaveResponse(result, client.get(), host,
                              quiche::GetQuicheCommandLineFlag(FLAGS_quiet),
                              i + 1, num_requests);
      } else if (response_code >= 300 && response_code < 400) {
        std::cout << "Redirect chain incomplete. Still getting redirect (" << response_code << ") after " << redirect_count << " redirects." << std::endl;
      } else {
        std::cout << "Redirect chain failed with response code (" << response_code << ") after " << redirect_count << " redirects." << std::endl;
        
        ResponseResult result;
        result.domain = host;
        result.original_ip = original_ip;
        result.redirected_domain = current_host;
        result.redirect_ip = client->server_address().host().ToString();
        result.status_code = response_code;
        result.response_body = client->latest_response_body();
        result.response_headers = client->latest_response_headers();
        result.ttfb = client->latest_ttfb();
        result.ttlb = client->latest_ttlb();
        
        ProcessAndSaveErrorResponse(result, quiche::GetQuicheCommandLineFlag(FLAGS_quiet),
                                    i + 1, num_requests);
      }
      
      if (quiche::GetQuicheCommandLineFlag(FLAGS_redirect_is_success)) {
        std::cout << "Request succeeded (redirect " << response_code << ")."
                  << std::endl;
      } else {
        std::cout << "Request failed (redirect " << response_code << ")."
                  << std::endl;
        if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
          return 1;
        }
      }
    } else {
      std::cout << "Request failed (" << response_code << ")." << std::endl;
      
      ResponseResult result;
      result.domain = host;
      result.original_ip = client->server_address().host().ToString();
      result.redirected_domain = "";
      result.redirect_ip = "";
      result.status_code = response_code;
      result.response_body = client->latest_response_body();
      result.response_headers = client->latest_response_headers();
      result.ttfb = client->latest_ttfb();
      result.ttlb = client->latest_ttlb();
      
      ProcessAndSaveErrorResponse(result, quiche::GetQuicheCommandLineFlag(FLAGS_quiet),
                                  i + 1, num_requests);
      
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
        return 1;
      }
    }

    if (i + 1 < num_requests) {  // There are more requests to perform.
      if (quiche::GetQuicheCommandLineFlag(FLAGS_one_connection_per_request)) {
        std::cout << "Disconnecting client between requests." << std::endl;
        client->Disconnect();
        if (!client->Initialize()) {
          std::cerr << "Failed to reinitialize client between requests."
                    << std::endl;
          return 1;
        }
        if (!client->Connect()) {
          std::cerr << "Failed to reconnect client between requests."
                    << std::endl;
          if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
            return 1;
          }
        }
      } else if (!quiche::GetQuicheCommandLineFlag(
                     FLAGS_disable_port_changes)) {
        // Change the ephemeral port.
        if (!client->ChangeEphemeralPort()) {
          std::cerr << "Failed to change ephemeral port." << std::endl;
          return 1;
        }
      }
    }
  }

  return 0;
}

}  // namespace quic
