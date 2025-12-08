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

namespace quic {
namespace {

// Language detection structure
struct LanguageScore {
  double total = 0.0;
  double unicode = 0.0;
  double words = 0.0;
  double phrases = 0.0;
  int unicode_matches = 0;
  int word_matches = 0;
  int phrase_matches = 0;
};

struct LanguageDetectionResult {
  std::string primary_language = "Unknown";
  std::string confidence = "Low";
  double score = 0.0;
  std::string reason;
  std::string declared_language = "none";
  size_t text_length = 0;
  std::map<std::string, LanguageScore> all_scores;
};

// Extract HTML lang attribute and detect languages in response body
LanguageDetectionResult DetectLanguages(const std::string& response_headers, const std::string& response_body) {
  LanguageDetectionResult result;
  
  // Convert to lowercase for case-insensitive matching
  auto to_lower = [](const std::string& s) {
    std::string out(s.size(), '\0');
    std::transform(s.begin(), s.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
  };
  
  std::string body_lower = to_lower(response_body);
  std::string headers_lower = to_lower(response_headers);
  
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
    result.confidence = "Low";
    result.reason = "Insufficient text content";
    return result;
  }
  
  // Language patterns with Iranian languages (using simple string matching instead of regex ranges)
  struct LanguagePattern {
    std::vector<std::string> common_words;
    std::vector<std::string> phrases; 
    std::vector<std::string> indicators;
  };
  
  std::map<std::string, LanguagePattern> language_patterns = {
    {"English", {
      {"the", "and", "for", "are", "but", "not", "you", "all", "can", "had", "her", "was", "one", "our", "out", "day", "get", "has", "him", "his", "how", "its", "may", "new", "now", "old", "see", "two", "way", "who", "boy", "did", "man", "men", "put", "say", "she", "too", "use"},
      {"about", "after", "again", "against", "before", "being", "below", "between", "during", "further", "having", "other", "since", "through", "under", "until", "while", "would", "could", "should"},
      {"english", "language", "content", "website"}
    }},
    {"Spanish", {
      {"que", "con", "una", "por", "para", "más", "como", "pero", "sus", "hasta", "desde", "cuando", "muy", "sin", "sobre", "también", "me", "se", "le", "da", "su", "un", "el", "en", "es", "no", "te", "lo", "mi", "tu", "él", "yo", "ha", "he", "si", "ya", "ti"},
      {"porque", "después", "entonces", "mientras", "durante", "aunque", "todavía", "siempre", "ningún", "algún"},
      {"español", "castellano", "idioma", "página"}
    }},
    {"French", {
      {"que", "les", "des", "est", "son", "une", "sur", "avec", "tout", "ses", "était", "être", "avoir", "lui", "dans", "ce", "il", "le", "de", "à", "un", "pour", "pas", "vous", "par", "sont", "sa", "cette", "au", "ne", "et", "en", "du", "elle", "la", "mais", "ou", "si", "nous", "on", "me", "te"},
      {"parce", "après", "pendant", "depuis", "jusqu", "avant", "toujours", "jamais", "beaucoup", "encore"},
      {"français", "langue", "contenu", "site"}
    }},
    {"German", {
      {"der", "die", "und", "in", "den", "von", "zu", "das", "mit", "sich", "des", "auf", "für", "ist", "im", "dem", "nicht", "ein", "eine", "als", "auch", "es", "an", "werden", "aus", "er", "hat", "dass", "sie", "nach", "wird", "bei", "einer", "um", "am", "sind", "noch", "wie", "einem", "über", "einen", "so", "zum", "war", "haben", "nur", "oder", "aber", "vor", "zur", "bis", "unter", "kann", "du", "sein", "wenn", "ich"},
      {"weil", "obwohl", "während", "nachdem", "bevor", "falls", "damit", "sodass"},
      {"deutsch", "sprache", "inhalt", "webseite"}
    }},
    {"Persian", {
      {"که", "این", "آن", "را", "به", "از", "در", "با", "یا", "تا", "اگر", "چون", "برای", "روی", "زیر", "کنار", "بین", "پیش", "پس", "بعد", "قبل", "حال", "هنوز", "همیشه", "هیچ", "کسی", "چیزی", "جایی", "وقتی", "چرا", "چگونه", "کجا"},
      {"چونکه", "بنابراین", "اما", "ولی", "اگرچه", "درحالیکه", "پیش از آن", "پس از آن"},
      {"فارسی", "پارسی", "ایران", "تهران", "اصفهان", "شیراز", "مشهد", "تبریز", "کرمان", "اهواز", "رشت", "قم", "کرج", "ارومیه"}
    }},
    {"Dari", {
      {"که", "این", "آن", "را", "به", "از", "در", "با", "یا", "تا", "اگر", "چون", "برای", "روی", "زیر", "کنار", "بین", "پیش", "پس", "بعد", "قبل", "حال", "هنوز", "همیشه", "هیچ", "کسی", "چیزی", "جایی", "وقتی", "چرا", "چگونه", "کجا"},
      {"چونکه", "بنابراین", "اما", "ولی", "اگرچه", "درحالیکه", "پیش از آن", "پس از آن"},
      {"دری", "افغانستان", "کابل", "هرات", "مزار", "قندهار", "جلال‌آباد", "غزنی", "بامیان"}
    }},
    {"Kurdish", {
      {"کە", "ئەم", "ئەو", "لە", "بۆ", "لەگەڵ", "یان", "تا", "ئەگەر", "چونکە", "بەهۆی", "سەر", "ژێر", "تەنیشت", "نێوان", "پێش", "پاش", "ئێستا", "هەمیشە", "هیچ", "کەس", "شت", "شوێن", "کاتێک", "بۆچی", "چۆن", "کوێ"},
      {"چونکە", "بۆیە", "بەڵام", "هەرچەندە", "لەکاتێکدا", "پێش ئەوەی", "پاش ئەوەی"},
      {"کوردی", "کوردستان", "هەولێر", "سلێمانی", "دهۆک", "کەرکووک", "زاخۆ", "قامشلی"}
    }},
    {"Pashto", {
      {"چې", "دا", "هغه", "ته", "له", "په", "سره", "یا", "تر", "که", "ځکه", "د", "پر", "لاندې", "ترڅنګ", "ترمنځ", "مخکې", "وروسته", "اوس", "تل", "هیڅ", "څوک", "ډېر", "ځای", "کله", "ولې", "څنګه", "چېرته"},
      {"ځکه چې", "نو", "مګر", "که څه هم", "پداسې حال کې چې", "دمخه", "وروسته"},
      {"پښتو", "افغانستان", "کابل", "قندهار", "هرات", "جلالاباد", "مزارشريف", "لښکرګاه", "پېښور", "کراچۍ"}
    }},
    {"Balochi", {
      {"کہ", "ای", "آ", "تئی", "گوں", "تہ", "یا", "تا", "اگاں", "چو", "واستہ", "بالا", "نیچ", "پاس", "مانز", "دیم", "پس", "ایشان", "ہمیشگی", "ہیچ", "کسے", "چیزے", "جاگہ", "کدے", "چے", "چون", "کجا"},
      {"چونکہ", "ایں واستہ", "لیکن", "اگرچی", "ایں وہد کہ", "ایں شئے", "ایں پس"},
      {"بلوچی", "بلوچستان", "کویٹہ", "زاہدان", "چابہار", "گوادر", "خاش", "سراوان", "قصر"}
    }},
    {"Arabic", {
      {"أن", "التي", "الذي", "في", "من", "إلى", "على", "هذا", "هذه", "ذلك", "تلك", "كان", "كانت", "ليس", "ليست", "أنه", "أنها", "الذين", "اللاتي", "والذي", "وإن", "كل", "بعد", "قبل", "عند", "عندما", "حين", "حيث", "كيف", "لماذا", "ماذا", "متى"},
      {"لأن", "ولكن", "ومع", "إذا", "عندما", "بينما", "حتى", "أو", "لكن"},
      {"العربية", "عربي", "لغة", "محتوى", "موقع"}
    }},
    {"Russian", {
      {"что", "это", "как", "так", "все", "она", "эта", "тот", "они", "мой", "наш", "для", "его", "при", "был", "том", "два", "где", "там", "чем", "них", "быть", "есть", "оно", "мне", "нас", "вас", "их", "себя", "тебя", "меня", "нами", "вами", "ними", "мной", "тобой", "собой"},
      {"потому", "после", "тогда", "пока", "хотя", "всегда", "никогда", "много", "ещё"},
      {"русский", "язык", "содержание", "сайт"}
    }},
    {"Chinese", {
      {"的", "了", "是", "在", "有", "我", "他", "这", "个", "们", "你", "来", "不", "到", "一", "上", "也", "为", "就", "学", "生", "会", "可", "以", "要", "对", "没", "说", "她", "好", "都", "和", "很", "给", "用", "过", "因", "请", "让", "从", "想"},
      {"因为", "所以", "但是", "然后", "如果", "虽然", "然而", "或者", "而且", "不过"},
      {"中文", "汉语", "语言", "内容", "网站"}
    }}
  };
  
  // Calculate scores for each language
  for (const auto& [language, pattern] : language_patterns) {
    LanguageScore& score = result.all_scores[language];
    
    // Count common words
    for (const std::string& word : pattern.common_words) {
      std::string word_lower = to_lower(word);
      size_t pos = 0;
      while ((pos = body_lower.find(word_lower, pos)) != std::string::npos) {
        score.word_matches++;
        pos += word_lower.length();
      }
    }
    
    // Count phrases
    for (const std::string& phrase : pattern.phrases) {
      std::string phrase_lower = to_lower(phrase);
      size_t pos = 0;
      while ((pos = body_lower.find(phrase_lower, pos)) != std::string::npos) {
        score.phrase_matches++;
        pos += phrase_lower.length();
      }
    }
    
    // Count language indicators
    for (const std::string& indicator : pattern.indicators) {
      std::string indicator_lower = to_lower(indicator);
      size_t pos = 0;
      while ((pos = body_lower.find(indicator_lower, pos)) != std::string::npos) {
        score.unicode_matches++;
        pos += indicator_lower.length();
      }
    }
    
    // Calculate component scores
    score.words = std::min(score.word_matches / (result.text_length / 100.0), 40.0);
    score.phrases = std::min(score.phrase_matches / (result.text_length / 200.0), 30.0);  
    score.unicode = std::min(score.unicode_matches / (result.text_length / 50.0), 30.0);
    
    score.total = score.words + score.phrases + score.unicode;
    
    // Boost score if language matches explicit declaration
    if (!result.declared_language.empty() && result.declared_language != "none") {
      std::map<std::string, std::string> lang_map = {
        {"en", "English"}, {"es", "Spanish"}, {"fr", "French"}, {"de", "German"},
        {"fa", "Persian"}, {"prs", "Dari"}, {"ku", "Kurdish"}, {"ps", "Pashto"},
        {"bal", "Balochi"}, {"ar", "Arabic"}, {"ru", "Russian"}, {"zh", "Chinese"}
      };
      
      std::string declared_code = result.declared_language.substr(0, 2);
      if (lang_map.count(declared_code) && lang_map[declared_code] == language) {
        score.total *= 1.5; // 50% boost for declared language
      }
    }
  }
  
  // Find the language with highest score
  if (!result.all_scores.empty()) {
    auto max_elem = std::max_element(result.all_scores.begin(), result.all_scores.end(),
      [](const auto& a, const auto& b) { return a.second.total < b.second.total; });
    
    result.primary_language = max_elem->first;
    result.score = max_elem->second.total;
    
    // Determine confidence level
    if (result.score >= 40) {
      result.confidence = "High";
      result.reason = "Strong language patterns detected";
    } else if (result.score >= 20) {
      result.confidence = "Medium";
      result.reason = "Moderate language patterns detected";
    } else if (result.score >= 5) {
      result.confidence = "Low";
      result.reason = "Weak language patterns detected";
    } else {
      result.confidence = "Very Low";
      result.reason = "Minimal language patterns detected";
    }
  }
  
  return result;
}

// -----------------------------------------------------------------------------
// Returns a non-empty reason string if the response looks geo-/region-blocked.
// Empty string  =>  no evidence of geo-restriction.
// -----------------------------------------------------------------------------
std::string GetGeoRestrictionReason(int http_status,
                                    const std::string& raw_headers,
                                    const std::string& body) {
  auto to_lower = [](const std::string& s) {
    std::string out(s.size(), '\0');
    std::transform(s.begin(), s.end(), out.begin(),
                   [](unsigned char c) { return std::tolower(c); });
    return out;
  };
  const std::string h = to_lower(raw_headers);
  const std::string b = to_lower(body);

  // ── 1. explicit codes ────────────────────────────────────────────────────
  if (http_status == 451)
    return "HTTP 451 – Unavailable for Legal/Geo Reasons";

  if (b.find("error 1009") != std::string::npos &&
      b.find("country")    != std::string::npos)
    return "Cloudflare Error 1009 (country/region banned)";

  // ── 2. header hints ──────────────────────────────────────────────────────
  for (std::string key :
       {"x-geo-block", "x-geo-restriction", "blocked-by", "country-denied"}) {
    if (h.find(key) != std::string::npos)
      return "Header \"" + key + "\" indicates geo-block";
  }

  // ── 3. high-confidence phrases ───────────────────────────────────────────
  for (std::string phrase : {
           "not available in your country", "not available in your region",
           "only works in", "only available in",
           "not supported in your region", "due to rights issues",
           "due to licensing restrictions",
           "sorry, disney+ is not available",
           "hulu isn",  // "Hulu isn't available in your location"
           "you seem to be using an unblocker or proxy"}) {
    if (b.find(phrase) != std::string::npos)
      return "Phrase \"" + phrase + "\" found in body";
  }

  // ── 4. softer heuristic: need ≥2 hits + suspicious status ────────────────
  if (http_status == 403 || http_status == 302 || http_status == 301) {
    int hits = 0;
    for (std::string soft : {"not available", "unavailable", "access denied",
                             "geo", "region", "country", "vpn", "outside"}) {
      if (b.find(soft) != std::string::npos) ++hits;
    }
    if (hits >= 2)
      return "Multiple geo keywords with HTTP " + std::to_string(http_status);
  }

  return {};  // no evidence
}

// Record a log entry in CSV format.
void AppendCsvLog(const std::string& log_filename,
                  const std::string& host,
                  const std::string& server_ip,
                  bool migration_disabled,
                  bool restriction_detected,
                  const std::string& reason,
                  size_t response_size,
                  int64_t ttlb_ms) {
  // Check if file exists and is empty
  struct stat st;
  bool write_header = (stat(log_filename.c_str(), &st) != 0) || (st.st_size == 0);

  std::ofstream log_file(log_filename, std::ios::app);
  if (log_file.is_open()) {
    if (write_header) {
      log_file << "host,server_ip,disable_conn_migration,restriction_detected,reason,response_size,ttlb_ms\n";
    }
    std::string escaped_reason = reason;
    size_t pos = 0;
    while ((pos = escaped_reason.find('"', pos)) != std::string::npos) {
      escaped_reason.insert(pos, 1, '"');
      pos += 2;
    }
    log_file << '"' << host << "\","
             << '"' << server_ip << "\","
             << (migration_disabled ? "1" : "0") << ","
             << (restriction_detected ? "1" : "0") << ","
             << '"' << escaped_reason << "\","
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
  proof_source->AddCertAndKey(
      {"*"},
      quiche::QuicheReferenceCountedPointer<ClientProofSource::Chain>(
          new ClientProofSource::Chain(certs)),
      std::move(*private_key));

  return proof_source;
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
    std::cerr << "Failed to connect to " << host << ":" << port 
              << "(" << client->server_address().host() << ":" << client->server_address().port() << ")"
              << ". " << quic::QuicErrorCodeToString(error) << " "
              << client->session()->error_details() << std::endl;
    return 1;
  }

  std::cout << "Connected to " << host << "("<< client->server_address().host() << ":" << port << 
   ") - Disable connection migration: " << client->session()->IsDisableConnectionMigration();
  if (quiche::GetQuicheCommandLineFlag(FLAGS_output_resolved_server_address)) {
    std::cout << ", resolved IP " << client->server_address().host().ToString();
  }
  std::cout << std::endl;
  
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

      std::string response_body = client->latest_response_body();
      // if (!quiche::GetQuicheCommandLineFlag(FLAGS_body_hex).empty()) {
      //   // Assume response is binary data.
      //   std::cout << "body:\n"
      //             << QuicheTextUtils::HexDump(response_body) << std::endl;
      // } else {
      //   std::cout << "body: " << response_body << std::endl;
      // }
      // std::cout << "trailers: " << client->latest_response_trailers()
      //           << std::endl;
      // std::cout << "early data accepted: " << client->EarlyDataAccepted()
      //           << std::endl;

      // if(ContainsGeoRestrictionKeywords(response_body)) {
      //   std::cout << "Response body contains geo-restriction keywords." << std::endl;
      // } else {
      //   std::cout << "Nope" << std::endl;
      // }

      std::string reason = GetGeoRestrictionReason(
          client->latest_response_code(), client->latest_response_headers(), response_body);
      if (!reason.empty()) {
        std::cout << "Geo-restriction detected: " << reason << "\n";
      } else {
        std::cout << "No geo-restriction detected.\n";
      }

      // Language detection
      LanguageDetectionResult lang_result = DetectLanguages(
          client->latest_response_headers(), response_body);
      
      std::cout << "\n=== Language Detection ===" << std::endl;
      std::cout << "Declared Language: " << lang_result.declared_language << std::endl;
      std::cout << "Primary Language: " << lang_result.primary_language 
                << " (Score: " << std::fixed << std::setprecision(1) << lang_result.score 
                << ", Confidence: " << lang_result.confidence << ")" << std::endl;
      std::cout << "Reason: " << lang_result.reason << std::endl;
      std::cout << "Text Length: " << lang_result.text_length << " characters" << std::endl;
      
      // Show top language scores
      if (!lang_result.all_scores.empty()) {
        std::cout << "Top Language Scores:" << std::endl;
        std::vector<std::pair<std::string, LanguageScore>> sorted_scores;
        for (const auto& [lang, score] : lang_result.all_scores) {
          sorted_scores.push_back({lang, score});
        }
        std::sort(sorted_scores.begin(), sorted_scores.end(),
          [](const auto& a, const auto& b) { return a.second.total > b.second.total; });
        
        for (size_t i = 0; i < std::min(size_t(5), sorted_scores.size()); ++i) {
          const auto& [lang, score] = sorted_scores[i];
          if (score.total > 0) {
            std::cout << "  " << (i+1) << ". " << lang << ": " 
                      << std::fixed << std::setprecision(1) << score.total
                      << " (U:" << score.unicode_matches 
                      << " W:" << score.word_matches 
                      << " P:" << score.phrase_matches << ")" << std::endl;
          }
        }
      }
      std::cout << "==========================\n" << std::endl;

      AppendCsvLog("quic_client_log.csv", host,
                   client->server_address().host().ToString(),
                   client->session()->IsDisableConnectionMigration(),
                   !reason.empty(), reason, response_body.size(),
                   client->latest_ttlb().ToMilliseconds());

      std::cout << "total received bytes: " << response_body.size() << std::endl;

      //std::cout << "-- skip --" << std::endl;
      std::cout << "Request completed with TTFB(ms): "
                     << client->latest_ttfb().ToMilliseconds() << ", TTLB(ms): "
                     << client->latest_ttlb().ToMilliseconds() << '\n';
    


      //std::cout << "-- skip --" << std::endl;
      QUIC_LOG(INFO) << "Request completed with TTFB(us): "
                     << client->latest_ttfb().ToMicroseconds() << ", TTLB(us): "
                     << client->latest_ttlb().ToMicroseconds();

      
    }

    if (!client->connected()) {
      std::cerr << "Request caused connection failure. Error: "
                << quic::QuicErrorCodeToString(client->session()->error())
                << std::endl;
      if (!quiche::GetQuicheCommandLineFlag(FLAGS_ignore_errors)) {
        return 1;
      }
    }

    int response_code = client->latest_response_code();
    if (response_code >= 200 && response_code < 300) {
      std::cout << "Request succeeded (" << response_code << ")." << std::endl;
    } else if (response_code >= 300 && response_code < 400) {
      // Handle redirects (301, 302, etc.) with loop for redirect chains
      int redirect_count = 0;
      const int max_redirects = 10; // Prevent infinite redirect loops
      
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
              std::cout << "Cleaned path from '//' to '" << clean_path << "'" << std::endl;
            }
            
            // Update header block with new URL
            header_block[":scheme"] = redirect_url.scheme();
            header_block[":authority"] = redirect_url.HostPort();
            header_block[":path"] = clean_path;
            
            // Follow the redirect
            std::cout << "Following redirect #" << redirect_count << "..." << std::endl;
            
            // Print redirect request headers before sending
            std::cout << "Redirect Request:" << std::endl;
            std::cout << "headers:" << header_block.DebugString();
            std::cout << std::endl;
            
            client->SendRequestAndWaitForResponse(header_block, body, /*fin=*/true);
            
            // Update response_code for the next iteration
            response_code = client->latest_response_code();

            // Print the redirected response headers and body
            std::cout << "Redirected Response #" << redirect_count << ":" << std::endl;
            std::cout << "Connected to redirected server: " << redirect_url.host() 
                      << "(" << client->server_address().host() << ":" 
                      << client->server_address().port() << ")" << std::endl;
            std::cout << "headers: " << client->latest_response_headers()
                      << std::endl;

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
      } else if (response_code >= 300 && response_code < 400) {
        std::cout << "Redirect chain incomplete. Still getting redirect (" << response_code << ") after " << redirect_count << " redirects." << std::endl;
      } else {
        std::cout << "Redirect chain failed with response code (" << response_code << ") after " << redirect_count << " redirects." << std::endl;
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
