#!/usr/bin/env bash
# Based on https://github.com/NixOS/infra/blob/ee40a029726aef3e35c4920492536c2879965f33/terraform/cache/diagnostic.sh
# MIT License
#
# Copyright (c) 2024 NixOS Foundation and contributors
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# We use debian packages for this script in case we can't hit cache.nixos.org
#
# Run this script if you are having issues with cache.nixos.org and paste the
# output URL in a new issue in the same repo.
#

domain=${1:-cache.nixos.org}

run() {
  echo "> $*"
  "$@" |& sed -e "s/^/    /"
  printf "Exit: %s\n\n\n" "$?"
}

curl_w="
time_namelookup:    %{time_namelookup}
time_connect:       %{time_connect}
time_appconnect:    %{time_appconnect}
time_pretransfer:   %{time_pretransfer}
time_redirect:      %{time_redirect}
time_starttransfer: %{time_starttransfer}
time_total:         %{time_total}
"

curl_test() {
  curl -w "$curl_w" -v -o /dev/null "$@"
}

echo "domain=$domain"
run dig -t A "$domain"
run ping -c1 "$domain"
run ping -c1 "$domain"
run ping6 -c1 "$domain"
run mtr -c 20 -w -r "$domain"
run curl_test -4 "http://$domain/"
run curl_test -6 "http://$domain/"
run curl_test -4 "https://$domain/"
run curl_test -6 "https://$domain/"
run curl -I -4 "https://$domain/"
run curl -I -4 "https://$domain/"
run curl -I -4 "https://$domain/"
run curl -I -6 "https://$domain/"
run curl -I -6 "https://$domain/"
run curl -I -6 "https://$domain/"
