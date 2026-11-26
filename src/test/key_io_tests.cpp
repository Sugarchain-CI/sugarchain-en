// Copyright (c) 2011-present The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <test/data/key_io_invalid.json.h>
#include <test/data/key_io_valid.json.h>

#include <common/args.h>
#include <key.h>
#include <key_io.h>
#include <script/script.h>
#include <test/util/json.h>
#include <test/util/setup_common.h>
#include <univalue.h>
#include <util/chaintype.h>
#include <util/strencodings.h>

#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <array>
#include <string_view>

BOOST_FIXTURE_TEST_SUITE(key_io_tests, BasicTestingSetup)

// Goal: check that parsed keys match test payload
BOOST_AUTO_TEST_CASE(key_io_valid_parse)
{
    UniValue tests = read_json(json_tests::key_io_valid);
    CKey privkey;
    CTxDestination destination;
    SelectParams(ChainType::MAIN);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) { // Allow for extra stuff (useful for comments)
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        const std::vector<std::byte> exp_payload{ParseHex<std::byte>(test[1].get_str())};
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        bool try_case_flip = metadata.find_value("tryCaseFlip").isNull() ? false : metadata.find_value("tryCaseFlip").get_bool();
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            // Must be valid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(privkey.IsValid(), "!IsValid:" + strTest);
            BOOST_CHECK_MESSAGE(privkey.IsCompressed() == isCompressed, "compressed mismatch:" + strTest);
            BOOST_CHECK_MESSAGE(std::ranges::equal(privkey, exp_payload), "key mismatch:" + strTest);

            // Private key must be invalid public key
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid privkey as pubkey:" + strTest);
        } else {
            // Must be valid public key
            destination = DecodeDestination(exp_base58string);
            CScript script = GetScriptForDestination(destination);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination), "!IsValid:" + strTest);
            BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));

            // Try flipped case version
            for (char& c : exp_base58string) {
                if (c >= 'a' && c <= 'z') {
                    c = (c - 'a') + 'A';
                } else if (c >= 'A' && c <= 'Z') {
                    c = (c - 'A') + 'a';
                }
            }
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(IsValidDestination(destination) == try_case_flip, "!IsValid case flipped:" + strTest);
            if (IsValidDestination(destination)) {
                script = GetScriptForDestination(destination);
                BOOST_CHECK_EQUAL(HexStr(script), HexStr(exp_payload));
            }

            // Public key must be invalid private key
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid pubkey as privkey:" + strTest);
        }
    }
}

// Goal: check that generated keys match test vectors
BOOST_AUTO_TEST_CASE(key_io_valid_gen)
{
    // Test the upstream address vectors with their original regtest encoding.
    m_node.args->ForceSetArg("-test", "bitcoinregtest");
    UniValue tests = read_json(json_tests::key_io_valid);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 3) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();
        std::vector<unsigned char> exp_payload = ParseHex(test[1].get_str());
        const UniValue &metadata = test[2].get_obj();
        bool isPrivkey = metadata.find_value("isPrivkey").get_bool();
        SelectParams(ChainTypeFromString(metadata.find_value("chain").get_str()).value());
        if (isPrivkey) {
            bool isCompressed = metadata.find_value("isCompressed").get_bool();
            CKey key;
            key.Set(exp_payload.begin(), exp_payload.end(), isCompressed);
            assert(key.IsValid());
            BOOST_CHECK_MESSAGE(EncodeSecret(key) == exp_base58string, "result mismatch: " + strTest);
        } else {
            CTxDestination dest;
            CScript exp_script(exp_payload.begin(), exp_payload.end());
            BOOST_CHECK(ExtractDestination(exp_script, dest));
            std::string address = EncodeDestination(dest);

            BOOST_CHECK_EQUAL(address, exp_base58string);
        }
    }

    SelectParams(ChainType::MAIN);
}

BOOST_AUTO_TEST_CASE(native_address_formats)
{
    const std::array<CTxDestination, 3> destinations{PKHash{}, ScriptHash{}, WitnessV0KeyHash{}};
    const std::array chains{ChainType::MAIN, ChainType::TESTNET, ChainType::REGTEST};
    const std::array<std::array<std::string_view, 3>, 3> prefixes{{
        {"S", "s", "sugar1q"},
        {"T", "t", "tugar1q"},
        {"R", "r", "rugar1q"},
    }};
    for (size_t i{0}; i < chains.size(); ++i) {
        SelectParams(chains[i]);
        for (size_t j{0}; j < destinations.size(); ++j) {
            const auto address{EncodeDestination(destinations[j])};
            BOOST_TEST_CONTEXT(address) {
                BOOST_CHECK(address.starts_with(prefixes[i][j]));
                BOOST_CHECK(DecodeDestination(address) == destinations[j]);
                for (const auto other_chain : chains) {
                    if (other_chain == chains[i]) continue;
                    SelectParams(other_chain);
                    BOOST_CHECK(!IsValidDestinationString(address));
                }
            }
            SelectParams(chains[i]);
        }
    }
    SelectParams(ChainType::MAIN);
}


// Native mainnet encodings must not be accepted on the inherited test networks.
BOOST_AUTO_TEST_CASE(key_io_mainnet_cross_network)
{
    const UniValue tests = read_json(json_tests::key_io_valid);
    for (unsigned int idx = 0; idx < tests.size(); ++idx) {
        const UniValue& test = tests[idx];
        const UniValue& metadata = test[2].get_obj();
        if (metadata.find_value("chain").get_str() != "main" || metadata.find_value("isPrivkey").get_bool()) continue;

        const std::string address = test[0].get_str();
        SelectParams(ChainType::MAIN);
        BOOST_REQUIRE_MESSAGE(IsValidDestination(DecodeDestination(address)), "Invalid native mainnet fixture: " + address);
        for (const auto chain : {ChainType::TESTNET, ChainType::TESTNET4, ChainType::SIGNET, ChainType::REGTEST}) {
            SelectParams(chain);
            BOOST_CHECK_MESSAGE(!IsValidDestination(DecodeDestination(address)), "Native mainnet address accepted on another network: " + address);
        }
    }
    SelectParams(ChainType::MAIN);
}

// Goal: check that base58 parsing code is robust against a variety of corrupted data
BOOST_AUTO_TEST_CASE(key_io_invalid)
{
    UniValue tests = read_json(json_tests::key_io_invalid); // Negative testcases
    CKey privkey;
    CTxDestination destination;

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];
        std::string strTest = test.write();
        if (test.size() < 1) // Allow for extra stuff (useful for comments)
        {
            BOOST_ERROR("Bad test: " << strTest);
            continue;
        }
        std::string exp_base58string = test[0].get_str();

        // must be invalid as public and as private key
        for (const auto& chain : {ChainType::MAIN, ChainType::TESTNET, ChainType::SIGNET, ChainType::REGTEST}) {
            SelectParams(chain);
            destination = DecodeDestination(exp_base58string);
            BOOST_CHECK_MESSAGE(!IsValidDestination(destination), "IsValid pubkey in mainnet:" + strTest);
            privkey = DecodeSecret(exp_base58string);
            BOOST_CHECK_MESSAGE(!privkey.IsValid(), "IsValid privkey in mainnet:" + strTest);
        }
    }
}

BOOST_AUTO_TEST_SUITE_END()
