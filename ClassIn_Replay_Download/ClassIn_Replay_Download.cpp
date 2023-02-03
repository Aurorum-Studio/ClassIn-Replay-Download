#include "httplib.h"
#include "CLI11.hpp"
#include "json.hpp"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <Windows.h>
#include <VersionHelpers.h>
#include <Psapi.h>

using namespace std;
using namespace httplib;
using json = nlohmann::json;

#define hex2int(x) (x <= '9' ? x - '0' : x - 'a' + 10)

vector<uint8_t> prefix_bin;
bool short_char = false, Running = true;
regex is_url("http(s)?://([\\w-]+\\.)+[\\w-]+(/[\\w- ./?%&=]*)?");
set<DWORD> ClassInPids;
map<DWORD, map<string, set<string> > > ReplayUrls, NewFoundUrls;

bool IsProcessRunAsAdmin()
{
    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    PSID AdministratorsGroup;
    BOOL b = AllocateAndInitializeSid(
        &NtAuthority,
        2,
        SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS,
        0, 0, 0, 0, 0, 0,
        &AdministratorsGroup);
    if (b)
    {
        CheckTokenMembership(NULL, AdministratorsGroup, &b);
        FreeSid(AdministratorsGroup);
    }
    return b == TRUE;
}

// Check whether a hex string is valid
string VerifyPrefix(string str)
{
    if (str.length() < 48)
        return "The length of prefix is at least 24 bytes";
    if (str.length() % 2)
        return "The length of prefix must be even";
    for (uint64_t i = 0; i < str.length(); i++)
        if (!(('0' <= str[i] && str[i] <= '9') || ('a' <= str[i] and str[i] <= 'f')))
            return "String can only include \"0123456789abcdef\"";
    return "";
}

bool compare_pred_w(WCHAR a, WCHAR b)
{
    return towlower(a) == towlower(b);
}
bool EndsWith_w(const wstring& str, const wstring& suffix)
{
    if (str.size() < suffix.size())
        return false;

    wstring tstr = str.substr(str.size() - suffix.size());

    if (tstr.length() == suffix.length())
        return equal(suffix.begin(), suffix.end(), tstr.begin(), compare_pred_w);
    else
        return false;
}

string asc_utf8(string in_str)
{
    int in_size, wide_size, utf8_size;
    wchar_t* wide_string;
    char* utf8_string;
    in_size = in_str.length();

    wide_size = MultiByteToWideChar(CP_ACP, 0, in_str.data(), in_size, NULL, 0);
    wide_string = (wchar_t*)malloc((wide_size + 1) * sizeof(wchar_t));
    ZeroMemory(wide_string, (wide_size + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, in_str.data(), in_size, wide_string, wide_size);

    utf8_size = WideCharToMultiByte(CP_UTF8, 0, wide_string, wide_size, NULL, 0, NULL, NULL);
    utf8_string = (char*)malloc(utf8_size + 1);
    ZeroMemory(utf8_string, utf8_size + 1);
    WideCharToMultiByte(CP_UTF8, 0, wide_string, wide_size, utf8_string, utf8_size, NULL, NULL);

    free(wide_string);
    return utf8_string;
}

string utf8_asc(string in_str)
{
    int in_size, wide_size, asc_size;
    wchar_t* wide_string;
    char* asc_string;
    in_size = in_str.length();

    wide_size = MultiByteToWideChar(CP_UTF8, 0, in_str.data(), in_size, NULL, 0);
    wide_string = (wchar_t*)malloc((wide_size + 1) * sizeof(wchar_t));
    ZeroMemory(wide_string, (wide_size + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, in_str.data(), in_size, wide_string, wide_size);

    asc_size = WideCharToMultiByte(CP_ACP, 0, wide_string, wide_size, NULL, 0, NULL, NULL);
    asc_string = (char*)malloc(asc_size + 1);
    ZeroMemory(asc_string, asc_size + 1);
    WideCharToMultiByte(CP_ACP, 0, wide_string, wide_size, asc_string, asc_size, NULL, NULL);

    free(wide_string);
    return asc_string;
}

vector<string> FindUrl(DWORD pid)
{
    vector<string> ret;
    string tmp_str;
    wstring tmp_wstr;
    size_t tmp_size;
    char* buffer;
    HANDLE h;
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, pid);
    if (h == 0)
        return ret;

    bool last = false;
    uint8_t* mem, * it;
    uint64_t size = prefix_bin.size(), i = 0;
    MEMORY_BASIC_INFORMATION info;
    SIZE_T res;

    mem = NULL;
    it = NULL;

    while (i < 0x00007fffffffffff)
    {
        mem = NULL;
        res = VirtualQueryEx(h, (void*)i, &info, sizeof(info));
        if (!res)
        {
            i += 1024;
            continue;
        }
        if (!(info.Protect & PAGE_READWRITE) || (info.Protect & PAGE_GUARD))
        {
            i = (uint64_t)info.BaseAddress + info.RegionSize;
            continue;
        }
        while (mem == NULL)
            mem = (uint8_t*)malloc(info.RegionSize);
        if (!ReadProcessMemory(h, (LPCVOID)info.BaseAddress, mem, info.RegionSize, NULL))
        {
            i = (uint64_t)info.BaseAddress + info.RegionSize;
            free(mem);
            continue;
        }
        it = search(mem, mem + info.RegionSize, prefix_bin.begin(), prefix_bin.end());
        while (it != mem + info.RegionSize)
        {
            if (short_char)
            {
                tmp_str = (char*)it;
            }
            else
            {
                tmp_wstr = (wchar_t*)it;
                tmp_size = WideCharToMultiByte(CP_ACP, 0, tmp_wstr.c_str(), tmp_wstr.size(), NULL, 0, NULL, NULL);
                buffer = new char[tmp_size + 1];
                WideCharToMultiByte(CP_ACP, 0, tmp_wstr.c_str(), tmp_wstr.size(), buffer, tmp_size, NULL, NULL);
                buffer[tmp_size] = '\0';
                tmp_str = buffer;
                delete[] buffer;
            }
            if (regex_match(tmp_str, is_url))
                ret.push_back(asc_utf8(tmp_str));
            it = search(it + 1, mem + info.RegionSize, prefix_bin.begin(), prefix_bin.end());
        }
        i = (uint64_t)info.BaseAddress + info.RegionSize;
        free(mem);
    }
    CloseHandle(h);
    return ret;
}

BOOL CALLBACK FindClassInPid(HWND hwnd, LPARAM lParam)
{
    int caption_len = GetWindowTextLengthW(hwnd) + 1;
    WCHAR* caption = (WCHAR*)malloc(sizeof(WCHAR) * (caption_len));
    GetWindowTextW(hwnd, caption, caption_len);
    if (!wcsstr(caption, L"ClassIn"))
    {
        free(caption);
        return TRUE;
    }
    free(caption);

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    HANDLE h;
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h == 0)
        return TRUE;
    WCHAR path[MAX_PATH];
    ZeroMemory(path, MAX_PATH * sizeof(WCHAR));
    GetModuleFileNameExW(h, NULL, path, MAX_PATH);
    CloseHandle(h);
    if (!EndsWith_w(path, L"ClassIn.exe"))
        return TRUE;
    ClassInPids.insert(pid);
    if (ReplayUrls.find(pid) == ReplayUrls.end())
        ReplayUrls[pid];
    return TRUE;
}

BOOL CALLBACK GetWindowTitles(HWND hwnd, LPARAM lParam)
{
    if (!IsWindowVisible(hwnd))
        return TRUE;

    DWORD pid;
    GetWindowThreadProcessId(hwnd, &pid);
    if (ClassInPids.find(pid) == ClassInPids.end())
        return TRUE;

    int caption_len = GetWindowTextLengthA(hwnd) + 1;
    CHAR* caption = (CHAR*)malloc(sizeof(WCHAR) * (caption_len));
    ZeroMemory(caption, sizeof(WCHAR) * (caption_len));
    GetWindowTextA(hwnd, caption, caption_len);
    string caption_str = asc_utf8(caption);
    free(caption);

    for (map<string, set<string> >::iterator i = NewFoundUrls[pid].begin(); i != NewFoundUrls[pid].end(); i++)
    {
        NewFoundUrls[pid][i->first].insert(caption_str);
    }

    return TRUE;
}

void ScanUrl()
{
    vector<string> CurrentUrls;
    ClassInPids.clear();
    NewFoundUrls.clear();
    EnumWindows(FindClassInPid, NULL);
    for (set<DWORD>::iterator i = ClassInPids.begin(); i != ClassInPids.end(); i++)
    {
        CurrentUrls = FindUrl(*i);
        for (int j = 0; j < CurrentUrls.size(); j++)
            NewFoundUrls[*i][CurrentUrls[j]];
    }
    EnumWindows(GetWindowTitles, NULL);
    for (map<DWORD, map<string, set<string> > >::iterator i = NewFoundUrls.begin(); i != NewFoundUrls.end(); i++)
        for (map<string, set<string> >::iterator j = (i->second).begin(); j != (i->second).end(); j++)
            for (set<string>::iterator k = (j->second).begin(); k != (j->second).end(); k++)
            {
                ReplayUrls[i->first][j->first].insert(*k);
                cerr << i->first << " " << utf8_asc(j->first) << " " << utf8_asc(*k) << "\n";
            }
}

DWORD WINAPI ScanThread(LPVOID lParam)
{
    while (Running)
    {
        Sleep(1000);
    }
    return 0;
}

int main(int argc, char** argv)
{
    if (!IsWindows10OrGreater())
    {
        cerr << "This program only supports Windows 10 or greater. \n";
        return 1;
    }

    uint16_t port = 2473;
    string prefix = "680074007400700073003a002f002f0070006c00610079006200610063006b002e00650065006f002e0063006e002f00";
    string ip = "127.0.0.1";
    bool no_admin = false, no_browser = false;
    CLI::App app{ "ClassIn Replay Video Downloader" };
    app.add_option("--ip", ip, "HTTP server IP");
    app.add_option("--port", port, "HTTP server port");
    app.add_option("--prefix", prefix, "Search prefix")->check(VerifyPrefix);
    app.add_flag("--short-char", short_char, "Prefix is given as short char instead of wide char");
    app.add_flag("--no-admin", no_admin, "Do not ask for Administrator's privilege");
    app.add_flag("--no-browser", no_browser, "Do not automatically open a browser");
    CLI11_PARSE(app, argc, argv);

    if ((!IsProcessRunAsAdmin()) && (!no_admin))
    {
        CHAR szPath[MAX_PATH], port_str[7];
        ZeroMemory(szPath, MAX_PATH * sizeof(CHAR));
        ZeroMemory(port_str, 7 * sizeof(CHAR));
        GetModuleFileNameA(NULL, szPath, MAX_PATH);
        string Params;
        Params.append("--ip ");
        Params.append(ip);
        Params.append(" --prefix ");
        Params.append(prefix);
        Params.append(" --port ");
        sprintf(port_str, "%d", port);
        Params.append(port_str);
        if (short_char)
            Params.append(" --short-char");
        HINSTANCE res = ShellExecuteA(NULL, "runas", szPath, Params.data(), NULL, SW_SHOW);
        if ((uint64_t)res > 32)
        {
            return 0;
        }
        else
        {
            cerr << "Warning: You are running this program without Administrator's privilege. \n";
        }
    }

    for (uint64_t i = 0; i < prefix.length(); i += 2)
        prefix_bin.push_back(hex2int(prefix[i]) * 16 + hex2int(prefix[i + 1]));

    DWORD tid;
    HANDLE tHandle;
    tHandle = CreateThread(NULL, 0, ScanThread, NULL, 0, &tid);
    if (!tHandle)
    {
        cerr << "Failed to start thread: " << GetLastError() << "\n";
        return 1;
    }

    Server svr;

    svr.Get("/", [](const Request& req, Response& res) {
        res.set_content("<!DOCTYPE html><html><head><meta http-equiv=\"Refresh\" content=\"0;/get-urls\"></head></html>", "text/html");
        });

    svr.Get("/get-urls", [](const Request& req, Response& res) {
        json res_json(ReplayUrls);
        res.set_content(res_json.dump(), "text/json");
        });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        Running = false;
        svr.stop();
        });

    if (!no_browser)
    {
        string url_open = "http://";
        if (strcmp(ip.data(), "0.0.0.0") == 0)
            url_open.append("127.0.0.1");
        else if (strcmp(ip.data(), "::") == 0)
            url_open.append("[::1]");
        else if (ip.find(":") != ip.npos)
        {
            url_open.append("[");
            url_open.append(ip);
            url_open.append("]");
        }
        else
            url_open.append(ip);
        url_open.append(":");
        CHAR port_str[7] = { 0 };
        sprintf(port_str, "%d", port);
        url_open.append(port_str);
        ShellExecuteA(NULL, "open", url_open.data(), NULL, NULL, SW_SHOW);
    }

    cout << "Start listening at " << ip << " (port " << port << " )\n";
    svr.listen(ip, port);

    return 0;
}