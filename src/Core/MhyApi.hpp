#pragma once

#include <string>
#include <string_view>
#include <format>
#include <random>
#include <sstream>
#include <optional>
#include <iostream>
#include <unordered_map>

#include <nlohmann/json.hpp>
#include <cpr/cpr.h>

#include "ApiDefs.hpp"
#include "CreateUUID.hpp"
#include "CryptoKit.h"
#include "UtilString.hpp"
#include "TimeStamp.hpp"

static const std::string device_id{ CreateUUID::CreateUUID4() };

[[nodiscard]] inline std::string DataSignAlgorithmVersionGen1(const std::string_view salt = mihoyobbs_salt_x6)
{
    const std::string time_now{ std::to_string(GetUnixTimeStampSeconds()) };
    std::random_device rd{};
    std::mt19937 gen{ rd() };
    int lower_bound{ 100001 };
    int upper_bound{ 200000 };
    std::uniform_int_distribution<int> dist(lower_bound, upper_bound);
    const std::string rand{ std::to_string(dist(gen)) };
    std::string m{ "salt=" + std::string(salt) + "&t=" + time_now + "&r=" + rand };
    return time_now + "," + rand + "," + Md5(m);
}

[[nodiscard]] inline std::string DataSignAlgorithmVersionGen2(const std::string_view body, const std::string_view query, const std::string_view salt = mihoyobbs_salt_x6)
{
    const std::string time_now{ std::to_string(GetUnixTimeStampSeconds()) };
    std::random_device rd{};
    std::mt19937 gen{ rd() };
    int lower_bound{ 100001 };
    int upper_bound{ 200000 };
    std::uniform_int_distribution<int> dist(lower_bound, upper_bound);
    const std::string rand{ std::to_string(dist(gen)) };
    std::string m{ "salt=" + std::string(salt) + "&t=" + time_now + "&r=" + rand + "&b=" + std::string(body) + "&q=" + std::string(query) };
    return time_now + "," + rand + "," + Md5(m);
}

inline std::string Encrypt(const std::string_view source)
{
    static constinit const char* PublicKey{
        "-----BEGIN PUBLIC KEY-----\n"
        "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDDvekdPMHN3AYhm/vktJT+YJr7"
        "cI5DcsNKqdsx5DZX0gDuWFuIjzdwButrIYPNmRJ1G8ybDIF7oDW2eEpm5sMbL9zs"
        "9ExXCdvqrn51qELbqj0XxtMTIpaCHFSI50PfPpTFV9Xt/hmyVwokoOXFlAEgCn+Q"
        "CgGs52bFoYMtyi+xEQIDAQAB\n"
        "-----END PUBLIC KEY-----"
    };
    return rsaEncrypt(source.data(), PublicKey);
}

inline cpr::Header GetRequestHeader()
{
    static cpr::Header headers{
        { "Content-Type", "application/json" },
        { "User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) miHoYoBBS/2.95.1" },
        { "Accept", "application/json" },
        { "x-rpc-aigis", "" },
        { "x-rpc-app_id", "bll8iq97cem8" },
        { "x-rpc-app_version", "2.95.1" },
        { "x-rpc-client_type", "2" },
        { "x-rpc-device_id", device_id },
        { "x-rpc-device_name", "" },
        { "x-rpc-game_biz", "bbs_cn" },
        { "x-rpc-sdk_version", "2.16.0" }
    };
    return headers;
}

inline std::string randomLowerAndNumberString(const size_t length)
{
    static constexpr std::string_view chars{ "abcdefghijklmnopqrstuvwxyz0123456789" };
    std::random_device rd{};
    std::mt19937 gen{ rd() };
    std::uniform_int_distribution<size_t> dist(0, chars.size() - 1);
    std::string result;
    result.reserve(length);
    for (size_t i{}; i < length; i++)
        result += chars[dist(gen)];
    return result;
}

static const std::string qr_login_device_id{ randomLowerAndNumberString(53) };

inline cpr::Header GetQRLoginHeader()
{
    return cpr::Header{
        { "Content-Type", "application/json" },
        { "User-Agent", "HYPContainer/1.1.4.133" },
        { "Accept", "application/json" },
        { "x-rpc-app_id", "ddxf5dufpuyo" },
        { "x-rpc-client_type", "3" },
        { "x-rpc-device_id", qr_login_device_id }
    };
}

inline std::string getMysUserName(const std::string_view uid)
{
    static constexpr std::string_view url = api::mhy::mys::userinfo;
    cpr::Header headers{ GetRequestHeader() };
    headers["DS"] = DataSignAlgorithmVersionGen2("", std::format("uid={}", uid), mihoyobbs_salt_x4);
    const auto response = cpr::Get(
        cpr::Url{ std::format("{}?uid={}", url, uid) },
        cpr::Header{ headers });

    try
    {
        const auto data = nlohmann::json::parse(response.text);
        if (data.value("retcode", -1) != 0)
            return {};
        if (!data["data"].contains("user_info"))
            return {};
        return data["data"]["user_info"].value("nickname", std::string{});
    }
    catch (...)
    {
        return {};
    }
}

inline std::tuple<std::string, std::string> CreateQRLogin()
{
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::passport::create_qr_login },
        cpr::Body{ "{}" },
        GetQRLoginHeader());

    const auto j = nlohmann::json::parse(response.text);
    if (j.value("retcode", -1) != 0)
        return { {}, {} };
    return { j["data"]["url"].get<std::string>(),
             j["data"]["ticket"].get<std::string>() };
}

inline std::tuple<int, std::string, std::string, std::string, std::string, std::string> QueryQRLoginStatus(const std::string_view ticket)
{
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::passport::query_qr_login_status },
        cpr::Body{ nlohmann::json{ { "ticket", ticket } }.dump() },
        GetQRLoginHeader());

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);
    if (retcode != 0)
        return { retcode, {}, {}, {}, {}, {} };

    const std::string status = j["data"].value("status", std::string{});
    std::string stoken{};
    if (j["data"].contains("tokens"))
    {
        for (const auto& token : j["data"]["tokens"])
        {
            if (token.value("token_type", 0) == 1)
            {
                stoken = token.value("token", std::string{});
                break;
            }
        }
    }
    std::string aid{};
    std::string mid{};
    std::string accountName{};
    if (j["data"].contains("user_info"))
    {
        aid = j["data"]["user_info"].value("aid", std::string{});
        mid = j["data"]["user_info"].value("mid", std::string{});
        accountName = j["data"]["user_info"].value("account_name", std::string{});
    }
    return { 0, status, stoken, aid, mid, accountName };
}

inline std::tuple<int, std::string> GetGameTokenByStoken(
    const std::string_view stoken,
    const std::string_view mid,
    const std::string_view stuid = "")
{
    cpr::Header headers{ GetRequestHeader() };
    std::string cookie{ "stoken=" + std::string(stoken) };
    if (!mid.empty())
        cookie += "; mid=" + std::string(mid);
    if (!stuid.empty())
        cookie += "; stuid=" + std::string(stuid);
    headers["Cookie"] = cookie;
    headers["DS"] = DataSignAlgorithmVersionGen1(mihoyobbs_salt_k2);

    const auto response = cpr::Get(
        cpr::Url{ api::mhy::takumi::game_token },
        cpr::Header{ headers });

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);

    if (retcode != 0)
        return { retcode, {} };

    return { 0, j["data"]["game_token"].get<std::string>() };
}

inline std::tuple<int, std::string, std::string> GetStokenByLoginTicket(
    const std::string_view login_ticket,
    const std::string_view login_uid)
{
    const std::string url{ std::string(api::mhy::takumi::multi_token) +
                           "?login_ticket=" + std::string(login_ticket) +
                           "&uid=" + std::string(login_uid) +
                           "&token_types=3" };
    const auto response = cpr::Get(cpr::Url{ url });

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);

    if (retcode != 0)
        return { retcode, {}, {} };

    std::string stoken{};
    std::string mid{};
    for (const auto& token : j["data"].at("list"))
    {
        const std::string name = token.value("name", std::string{});
        if (name == "stoken")
            stoken = token.value("token", std::string{});
        else if (name == "mid")
            mid = token.value("token", std::string{});
    }
    return { 0, stoken, mid };
}

inline std::tuple<int, GeetestData> CreateLoginCaptcha(
    const std::string_view mobile,
    const std::string_view aigis = "")
{
    const std::string body{ nlohmann::json{
        { "area_code", Encrypt("+86") },
        { "mobile", Encrypt(mobile) } }
                                .dump() };
    cpr::Header reqHeaders{ GetRequestHeader() };
    reqHeaders["DS"] = DataSignAlgorithmVersionGen2(body, "", mihoyobbs_salt_prod);
    if (!aigis.empty())
        reqHeaders["X-Rpc-Aigis"] = aigis;
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::passport::create_captcha },
        cpr::Body{ body },
        cpr::Header{ reqHeaders });

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);
    GeetestData result{};
    if (retcode == 0)
    {
        result.action_type = j["data"].value("action_type", std::string{});
        return { retcode, result };
    }
    if (retcode == -3101)
    {
        const auto it = response.header.find("X-Rpc-Aigis");
        if (it != response.header.end())
        {
            const auto aigisJson = nlohmann::json::parse(it->second);
            const auto captchaJson = nlohmann::json::parse(aigisJson["data"].get<std::string>());

            result.session_id = aigisJson["session_id"].get<std::string>();
            result.mmt_type = aigisJson["mmt_type"].get<int>();
            result.gt = captchaJson["gt"].get<std::string>();
            result.challenge = captchaJson["challenge"].get<std::string>();
            result.GeeTestType = ServerType::Official;
        }
    }
    return { retcode, result };
}

inline auto LoginByMobileCaptcha(const std::string_view actionType, const std::string_view mobile, const std::string_view captcha, const std::string_view aigis = "")
{
    struct
    {
        int retcode{};
        struct
        {
            std::string V2Token{};
            std::string aid{};
            std::string mid{};
            std::string name{};
        } data;
    } result;

    const std::string body{ nlohmann::json{
        { "area_code", Encrypt("+86") },
        { "action_type", actionType },
        { "captcha", captcha },
        { "mobile", Encrypt(mobile) } }
                                .dump() };
    cpr::Header reqHeaders{ GetRequestHeader() };
    reqHeaders["DS"] = DataSignAlgorithmVersionGen2(body, "", mihoyobbs_salt_prod);
    if (!aigis.empty())
        reqHeaders["X-Rpc-Aigis"] = aigis;

    const auto response = cpr::Post(
        cpr::Url{ api::mhy::passport::login_by_mobile_captcha },
        cpr::Body{ body },
        cpr::Header{ reqHeaders });

    const auto j = nlohmann::json::parse(response.text);
    result.retcode = j.value("retcode", -1);
    if (result.retcode == 0)
    {
        result.data.V2Token = j["data"]["token"].value("token", std::string{});
        result.data.aid = j["data"]["user_info"].value("aid", std::string{});
        result.data.mid = j["data"]["user_info"].value("mid", std::string{});
        result.data.name = j["data"]["user_info"].value("account_name", std::string{});
    }
    return result;
}

inline bool ScanQRLogin(const std::string_view url, const std::string_view ticket, GameType gameType)
{
    cpr::Header headers{ GetRequestHeader() };
    headers["Content-Type"] = "application/json";
    headers["x-rpc-app_id"] = "bll8iq97cem8";
    headers["x-rpc-game_biz"] = "bbs_cn";
    const auto response = cpr::Post(
        cpr::Url{ url },
        cpr::Body{ nlohmann::json{
            { "app_id", static_cast<int>(gameType) },
            { "device", device_id },
            { "ticket", ticket } }
                       .dump() },
        cpr::Header{ headers });

    const auto j = nlohmann::json::parse(response.text);
    return j.value("retcode", -1) == 0;
}

inline bool ConfirmQRLogin(const std::string_view url, const std::string_view uid, const std::string_view gameToken, const std::string_view ticket, GameType gameType)
{
    cpr::Header headers{ GetRequestHeader() };
    headers["Content-Type"] = "application/json";
    headers["x-rpc-app_id"] = "bll8iq97cem8";
    headers["x-rpc-game_biz"] = "bbs_cn";
    const auto response = cpr::Post(
        cpr::Url{ url },
        cpr::Body{ nlohmann::json{
            { "app_id", static_cast<int>(gameType) },
            { "device", device_id },
            { "ticket", ticket },
            { "payload", { { "proto", "Account" }, { "raw", nlohmann::json{ { "uid", uid }, { "token", gameToken } }.dump() } } } }
                       .dump() },
        cpr::Header{ headers });

    const auto j = nlohmann::json::parse(response.text);
    return j.value("retcode", -1) == 0;
}

inline std::string makeSign(const nlohmann::json& data)
{
    std::string param;
    for (auto& [key, value] : data.items())
    {
        if (key == "sign")
            continue;
        const std::string strVal = value.is_string() ? value.get<std::string>() : value.dump();

        param += key + "=" + strVal + "&";
    }
    if (!param.empty())
        param.pop_back();
#ifdef _DEBUG
    std::cout << "make_param = " << param << std::endl;
#endif
    constexpr std::string_view key = "0ebc517adb1b62c6b408df153331f9aa";
    return HmacSha256(param, std::string(key));
}

inline std::string& getOAString()
{
    static std::string value = []() {
        try
        {
            const auto response = cpr::Get(
                cpr::Url{ "https://api.v6qbb.cloud/get_bh3_bilibili_oa" },
                cpr::Timeout{ std::chrono::seconds{ 10 } });
            if (response.text.empty())
                return std::string{};
            return response.text;
        }
        catch (...)
        {
            return std::string{};
        }
    }();
    return value;
}

inline std::tuple<int, std::string, std::string, std::string> GetBH3ExternalLoginInfo(const std::string& uid, const std::string& access_key)
{
    const std::string bodyData = std::format(R"({{"access_key":"{}","uid":{}}})", access_key, uid);

    nlohmann::json body{
        { "device", "0000000000000000" },
        { "app_id", 1 },
        { "channel_id", 14 },
        { "data", bodyData }
    };
    body["sign"] = makeSign(body);
    cpr::Header headers{ GetRequestHeader() };
    headers["Content-Type"] = "application/json";
    headers["x-rpc-app_id"] = "bll8iq97cem8";
    headers["x-rpc-game_biz"] = "bbs_cn";
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::bh3::v2_login },
        cpr::Header{ headers },
        cpr::Body{ body.dump() });

    const auto j = nlohmann::json::parse(response.text);
    const int retcode = j.value("retcode", -1);

#ifdef _DEBUG
    std::cout << "崩坏3验证完成 : " << response.text << std::endl;
#endif

    if (retcode != 0)
    {
        return { retcode, {}, {}, {} };
    }

    return { 0,
             j["data"]["open_id"].get<std::string>(),
             j["data"]["combo_token"].get<std::string>(),
             j["data"]["combo_id"].get<std::string>() };
}

inline ScanRet scanCheck(const std::string& ticket)
{
    const std::string body = nlohmann::json{
        { "app_id", "1" },
        { "device", "0000000000000000" },
        { "ticket", ticket },
        { "ts", GetUnixTimeStampSeconds() }
    }.dump();

    cpr::Header headers{ GetRequestHeader() };
    headers["Content-Type"] = "application/json";
    headers["x-rpc-app_id"] = "bll8iq97cem8";
    headers["x-rpc-game_biz"] = "bbs_cn";
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::bh3::qrcode_scan },
        cpr::Body{ body },
        cpr::Header{ headers });

    const auto j = nlohmann::json::parse(response.text);
    return j.value("retcode", -1) == 0 ? ScanRet::SUCCESS : ScanRet::FAILURE_1;
}

inline ScanRet scanConfirm(const std::string& ticket, const std::string& uid, const std::string& access_key, const std::string& name)
{
    auto [code, open_id, combo_token, combo_id] = GetBH3ExternalLoginInfo(uid, access_key);
    if (code != 0)
        return ScanRet::FAILURE_2;

    const auto raw =
        nlohmann::json{
            { "heartbeat", false },
            { "open_id", open_id },
            { "device_id", "0000000000000000" },
            { "app_id", "1" },
            { "channel_id", "14" },
            { "combo_token", combo_token },
            { "asterisk_name", name },
            { "combo_id", combo_id },
            { "account_type", "2" }
        };

    const auto ext =
        nlohmann::json{
            { "data", nlohmann::json{
                          { "accountType", "2" },
                          { "accountID", "" },
                          { "c", open_id },
                          { "accountToken", combo_token },
                          { "dispatch", getOAString() } } }
        };

    const nlohmann::json postBody{
        { "device", "0000000000000000" },
        { "app_id", 1 },
        { "ts", GetUnixTimeStampSeconds() },
        { "ticket", ticket },
        { "payload", nlohmann::json{
                         { "proto", "Combo" },
                         { "raw", raw.dump() },
                         { "ext", ext.dump() } } }
    };

#ifdef _DEBUG
    std::cout << postBody.dump() << std::endl;
#endif

    cpr::Header headers{ GetRequestHeader() };
    headers["Content-Type"] = "application/json";
    headers["x-rpc-app_id"] = "bll8iq97cem8";
    headers["x-rpc-game_biz"] = "bbs_cn";
    const auto response = cpr::Post(
        cpr::Url{ api::mhy::bh3::qrcode_confirm },
        cpr::Header{ headers },
        cpr::Body{ postBody.dump() });

    const auto j = nlohmann::json::parse(response.text);
    return j.value("retcode", -1) == 0 ? ScanRet::SUCCESS : ScanRet::FAILURE_2;
}