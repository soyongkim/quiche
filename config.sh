#!/bin/bash
# config.sh: Central configuration file for common settings

# QUIC server
# SERVER_HOST="clnode154.clemson.cloudlab.us"
# SERVER_PORT="6121"


# SERVER_HOST="www.google.com"
# SERVER_HOST="www.youtube.com"

# SERVER_HOST="www.linkedin.com"
# SERVER_HOST="cloudflare-quic.com"

# SERVER_HOST="thepiratebay.se"

# SERVER_HOST="www.coupangplay.com"

SERVER_HOST="tubitv.com"

# SERVER_HOST="speed.cloudflare.com"


# If the web server uses the cloudflare, it looks like supporting QUIC 
# SERVER_HOST="arca.live"

# Ok, it's using Cloudflare, but the server quickly sent CC.
# SERVER_HOST="vimeo.com"

# It's also using Cloudflare, and the server supported QUIC.
# SERVER_HOST="www.w3.org"


# Akamai Case
# SERVER_HOST="www.akamai.com"

# IT's using Akamai, but the server didn't sent any response. it looks like doesn't support QUIC.
# SERVER_HOST="microsoft.com"
# SERVER_HOST="irs.gov"
# SERVER_HOST="cisco.com"


# It's the same case with vimeo.com. it's using Akamai, but the server quickly sent CC.
# SERVER_HOST="dan.com"
# SERVER_HOST="mailchimp.com"
# SERVER_HOST="marriott.com"


# cdn77, it supports QUIC, but sent CC quickly.
# SERVER_HOST="www.cdn77.com"


SERVER_PORT="443"

# path configuration
MAIN_IF="wlan0"
ALT_IF=""

# SERVER_HOST="www.microsoft.com"


# disbled active migration option !!
# SERVER_HOST="cloudflare-quic.com"
# SERVER_HOST="facebook.com"
# SERVER_PORT="443"


# MASQUE proxy
MASQUE_HOST="1.1.1.1"
MASQUE_PORT="9661"


# # main path
# MAIN_IF="wlan0"

# # alt path
# ALT_IF="tun0"




# Quic Version
# QUIC_VERSION="RFCv1"

