#!/usr/bin/env bash
# Copyright (c) 2026 The Sugarchain En developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or https://opensource.org/license/mit/.

export LC_ALL=C
set -euo pipefail

die() {
    printf '%s\n' "$*" >&2
    exit 1
}

if [[ $# -ne 4 ]]; then
    die "Usage: $0 APP OUTPUT.zip 'Developer ID Application: NAME (TEAM_ID)' NOTARY_PROFILE"
fi
[[ "$(uname -s)" == Darwin ]] || die "Run this script on macOS with Xcode command-line tools."

bundle_name=Sugarchain-Qt.app
source_app="${1%/}"
output=$2
identity=$3
notary_profile=$4
[[ $source_app == /* ]] || source_app="$PWD/$source_app"
[[ $output == /* ]] || output="$PWD/$output"
[[ ${source_app##*/} == "$bundle_name" && -d "$source_app" && ! -L "$source_app" ]] ||
    die "Expected a staged $bundle_name bundle."
[[ $output == *.zip && ! -e "$output" && ! -L "$output" ]] ||
    die "Choose a new output ZIP path."
[[ $identity == 'Developer ID Application: '?* && -n $notary_profile ]] ||
    die "A Developer ID Application identity and a notarytool keychain profile are required."

# Stage beside the output so the validated archive can be published atomically.
work=$(mktemp -d "$(dirname "$output")/.sugarchain-notary.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

app="$work/$bundle_name"
ditto "$source_app" "$app"
executable="$app/Contents/MacOS/Sugarchain-Qt"
info="$app/Contents/Info.plist"
[[ -x "$executable" && -f "$executable" && ! -L "$executable" && -f "$info" ]] ||
    die "Invalid $bundle_name bundle."
[[ "$(plutil -extract CFBundleIdentifier raw -o - "$info")" == org.sugarchain.SugarchainEn &&
   "$(plutil -extract CFBundleExecutable raw -o - "$info")" == Sugarchain-Qt ]] ||
    die "Invalid $bundle_name bundle metadata."

# Release builds link Qt statically. Refuse nested code that would need its
# own Developer ID signature before the outer bundle is signed.
find "$app" \( -type l -o -type f \) ! -path "$executable" -print0 > "$work/members"
while IFS= read -r -d '' member; do
    [[ ! -L "$member" && "$(file -b "$member")" != *Mach-O* ]] ||
        die "Unexpected nested code or symbolic link in the static release bundle: $member"
done < "$work/members"

codesign --force --sign "$identity" --options runtime --timestamp "$app"
codesign --verify --deep --strict "$app"
signature=$(codesign --display --verbose=4 "$app" 2>&1)
grep -Fxq "Authority=$identity" <<< "$signature" ||
    die "The app signature does not use the requested Developer ID Application identity."

# Apple accepts a ZIP submission and staples its ticket to the app inside.
submission="$work/submission.zip"
response="$work/submission.json"
ditto -c -k --sequesterRsrc --keepParent "$app" "$submission"
if ! xcrun notarytool submit "$submission" --keychain-profile "$notary_profile" --wait --output-format json > "$response"; then
    cat "$response" >&2
    die "The notarization command failed."
fi
status=$(plutil -extract status raw -o - "$response")
submission_id=$(plutil -extract id raw -o - "$response")
printf 'Notarization %s: %s\n' "$submission_id" "$status"
[[ $status == Accepted ]] ||
    die "Review the submission with xcrun notarytool log $submission_id and the same keychain profile."
xcrun stapler staple "$app"

# Repack the stapled app and verify the extracted distribution artifact.
distribution="$work/distribution.zip"
ditto -c -k --sequesterRsrc --keepParent "$app" "$distribution"
ditto -x -k "$distribution" "$work/check"
checked_app="$work/check/$bundle_name"
codesign --verify --deep --strict "$checked_app"
xcrun stapler validate "$checked_app"
spctl --assess --type execute --verbose=4 "$checked_app"
python3 -c 'import os, sys; os.link(sys.argv[1], sys.argv[2])' "$distribution" "$output"
printf 'Verified notarized package: %s\n' "$output"
