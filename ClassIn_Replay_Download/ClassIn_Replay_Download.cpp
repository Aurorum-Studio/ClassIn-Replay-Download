#include "resource.h"

#include "httplib.h"
#include "CLI11.hpp"
#include "json.hpp"

#include <string>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <regex>
#include <mutex>
#include <semaphore>
#include <Windows.h>
#include <VersionHelpers.h>
#include <Psapi.h>
#include <ShlObj.h>

extern "C" {
#include <libavutil/timestamp.h>
#include <libavformat/avformat.h>
#pragma comment(lib, "libffmpeg.lib")
}

using namespace std;
using namespace httplib;
using json = nlohmann::json;

#define hex2int(x) (x <= '9' ? x - '0' : x - 'a' + 10)

struct down_param {
    string infile;
    string outfile;
    uint64_t index;
};

struct down_t_param {
    string path;
    string filename;
    string url;
};

struct DownloadStatus {
    string url;
    string path;
    string filename;
    string fallback_filename;
    vector<double> percentage;
    uint8_t status;
#define DOWNLOADING 1
#define DOWNLOAD_FAILED 2
#define DOWNLOAD_CANCELLED 3
#define DOWNLOAD_SUCCEEDED 4
#define DOWNLOAD_WAITING 5
    string err_msg;
};

vector<uint8_t> prefix_bin;
bool short_char = false, Running = true, require_scan = false, auto_scan = true;
uint64_t wait_int = 5000, next_scan = 0;
regex is_url("http(s)?://([\\w-]+\\.)+[\\w-]+(/[\\w- ./?%&=]*)?");
set<DWORD> ClassInPids;
mutex lock_url;
map<DWORD, set<string>> ReplayUrls;
map<string, set<string>> url_title;
map<DWORD, map<string, set<string>>> NewFoundUrls;

mutex lock_down_status;
counting_semaphore<3> download_lock{ 3 };
vector<DownloadStatus> Downloads;
down_t_param new_down_args;
binary_semaphore start_down_thread_lock(1);

mutex lock_scan; // Just in case

CHAR* pwd;

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

vector<uint8_t> GetResource(uint32_t ResId, LPCWSTR Type)
{
    vector<uint8_t> nul_vec;
    HMODULE ghmodule = GetModuleHandleW(NULL);
    if (!ghmodule)
    {
        cerr << "Failed to get ghmodule\n";
        return nul_vec;
    }
    HRSRC hrsrc = FindResourceW(ghmodule, MAKEINTRESOURCE(ResId), Type);
    if (!hrsrc)
    {
        cerr << "Failed to get hrsrc\n";
        return nul_vec;
    }
    HGLOBAL hg = LoadResource(ghmodule, hrsrc);
    if (hg == NULL)
    {
        cerr << "Failed to get hg\n";
        return nul_vec;
    }
    unsigned char* addr = (unsigned char*)(LockResource(hg));
    if (!addr)
        cerr << "Failed to get addr\n";
    DWORD size = SizeofResource(ghmodule, hrsrc);
    vector<uint8_t> ret(addr, addr + size);
    return ret;
}
string vec2str(vector<uint8_t> vec)
{
    string out;
    out.assign(vec.begin(), vec.end());
    return out;
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
bool compare_pred(CHAR a, CHAR b)
{
    return tolower(a) == tolower(b);
}
bool EndsWith(const string& str, const string& suffix)
{
    if (str.size() < suffix.size())
        return false;

    string tstr = str.substr(str.size() - suffix.size());

    if (tstr.length() == suffix.length())
        return equal(suffix.begin(), suffix.end(), tstr.begin(), compare_pred_w);
    else
        return false;
}

vector<string> regex_split(string s, regex re)
{
    vector<string> res(sregex_token_iterator(s.begin(), s.end(), re, -1), sregex_token_iterator());
    return res;
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

string w_asc(wstring in_str)
{
    int in_size, asc_size;
    char* asc_string;
    in_size = in_str.length();
    asc_size = WideCharToMultiByte(CP_ACP, 0, in_str.data(), in_size, NULL, 0, NULL, NULL);
    asc_string = (char*)malloc(asc_size + 1);
    ZeroMemory(asc_string, asc_size + 1);
    WideCharToMultiByte(CP_ACP, 0, in_str.data(), in_size, asc_string, asc_size, NULL, NULL);
    return asc_string;
}

wstring asc_w(string in_str)
{
    int in_size, wide_size;
    wchar_t* wide_string;
    in_size = in_str.length();

    wide_size = MultiByteToWideChar(CP_ACP, 0, in_str.data(), in_size, NULL, 0);
    wide_string = (wchar_t*)malloc((wide_size + 1) * sizeof(wchar_t));
    ZeroMemory(wide_string, (wide_size + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_ACP, 0, in_str.data(), in_size, wide_string, wide_size);
    return wide_string;
}

wstring utf8_w(string in_str)
{
    int in_size, wide_size;
    wchar_t* wide_string;
    in_size = in_str.length();

    wide_size = MultiByteToWideChar(CP_UTF8, 0, in_str.data(), in_size, NULL, 0);
    wide_string = (wchar_t*)malloc((wide_size + 1) * sizeof(wchar_t));
    ZeroMemory(wide_string, (wide_size + 1) * sizeof(wchar_t));
    MultiByteToWideChar(CP_UTF8, 0, in_str.data(), in_size, wide_string, wide_size);
    return wide_string;
}

BOOL FindFirstFileExists(LPCTSTR lpPath, DWORD dwFilter)
{
    WIN32_FIND_DATAW fd;
    HANDLE hFind = FindFirstFileW(lpPath, &fd);
    BOOL bFilter = (FALSE == dwFilter) ? TRUE : fd.dwFileAttributes & dwFilter;
    BOOL RetValue = ((hFind != INVALID_HANDLE_VALUE) && bFilter) ? TRUE : FALSE;
    FindClose(hFind);
    return RetValue;
}

BOOL FilePathExists(LPCTSTR lpPath)
{
    return FindFirstFileExists(lpPath, FALSE);
}

string GetUniqueFilename(string path, string filename)
{
    string path_new = path;
    if (!EndsWith(path_new, "\\"))
        path_new += "\\";
    if (FilePathExists(utf8_w(path_new + filename).data()))
    {
        uint64_t add_suffix = 1;
        regex rename_start(R"((.*\()(\d+)(\)(\.[^.]*|)))"), split_name(R"((.*)(\.[^\.]*))");
        smatch match_result;
        string name_prefix, name_suffix = ")";
        if (regex_match(filename, match_result, rename_start))
        {
            stringstream ss;
            ss << match_result[2];
            ss >> add_suffix;
            name_prefix = match_result[1];
            name_suffix = match_result[3];
        }
        else
        {
            regex_match(filename, match_result, split_name);
            name_prefix = match_result[1];
            name_prefix += "(";
            name_suffix += match_result[2];
        }
        while (1)
        {
            add_suffix += 1;
            if (!FilePathExists(utf8_w(path_new + name_prefix + to_string(add_suffix) + name_suffix).data()))
                return name_prefix + to_string(add_suffix) + name_suffix;
        }
    }
    else
        return filename;
}

vector<string> FindUrl(DWORD pid)
{
    vector<string> ret;
    string tmp_str;
    wstring tmp_wstr;
    size_t tmp_size;
    char* buffer;
    HANDLE h;
    h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, FALSE, pid);
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
            if (regex_match(tmp_str, is_url) && !EndsWith(tmp_str, "?"))
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
    lock_scan.lock();
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
    lock_url.lock();
    for (map<DWORD, map<string, set<string> > >::iterator i = NewFoundUrls.begin(); i != NewFoundUrls.end(); i++)
        for (map<string, set<string> >::iterator j = (i->second).begin(); j != (i->second).end(); j++)
            for (set<string>::iterator k = (j->second).begin(); k != (j->second).end(); k++)
            {
                if (!url_title[j->first].contains(*k))
                    cerr << i->first << " " << utf8_asc(j->first) << " " << utf8_asc(*k) << "\n";
                ReplayUrls[i->first].insert(j->first);
                url_title[j->first].insert(*k);
            }
    lock_url.unlock();
    lock_scan.unlock();
}

DWORD WINAPI ScanThread(LPVOID lParam)
{
    uint64_t time;
    while (Running)
    {
        Sleep(50);
        time = GetTickCount64();
        if (require_scan)
        {
            require_scan = false;
            next_scan = time + wait_int;
            ScanUrl();
            continue;
        }
        if (auto_scan && time > next_scan)
        {
            require_scan = false;
            next_scan = time + wait_int;
            ScanUrl();
        }
    }
    return 0;
}

int32_t remux(down_param param)
{
    const AVOutputFormat* ofmt = NULL;
    AVFormatContext* ifmt_ctx = NULL, * ofmt_ctx = NULL;
    AVPacket* pkt = NULL;
    char* in_filename, * out_filename;
    int ret, i;
    int stream_index = 0;
    int* stream_mapping = NULL;
    int stream_mapping_size = 0;
    vector<int64_t> last_dts;

    in_filename = (char*)param.infile.data();
    out_filename = (char*)param.outfile.data();

    pkt = av_packet_alloc();
    if (!pkt) {
        lock_down_status.lock();
        Downloads[param.index].err_msg = "Could not allocate AVPacket";
        Downloads[param.index].status = DOWNLOAD_FAILED;
        lock_down_status.unlock();
        return 1;
    }

    if ((ret = avformat_open_input(&ifmt_ctx, in_filename, 0, 0)) < 0) {
        lock_down_status.lock();
        Downloads[param.index].err_msg = "Could not open input file";
        Downloads[param.index].status = DOWNLOAD_FAILED;
        lock_down_status.unlock();
        goto end;
    }

    if ((ret = avformat_find_stream_info(ifmt_ctx, 0)) < 0) {
        lock_down_status.lock();
        Downloads[param.index].err_msg = "Failed to retrieve input stream information";
        Downloads[param.index].status = DOWNLOAD_FAILED;
        lock_down_status.unlock();
        goto end;
    }

    av_dump_format(ifmt_ctx, 0, in_filename, 0);

    avformat_alloc_output_context2(&ofmt_ctx, NULL, NULL, out_filename);
    if (!ofmt_ctx) {
        lock_down_status.lock();
        Downloads[param.index].err_msg = "Could not create output context";
        Downloads[param.index].status = DOWNLOAD_FAILED;
        lock_down_status.unlock();
        ret = AVERROR_UNKNOWN;
        goto end;
    }

    stream_mapping_size = ifmt_ctx->nb_streams;
    stream_mapping = (int*)av_calloc(stream_mapping_size, sizeof(*stream_mapping));
    if (!stream_mapping) {
        ret = AVERROR(ENOMEM);
        lock_down_status.lock();
        Downloads[param.index].err_msg = "Unknown error";
        Downloads[param.index].status = DOWNLOAD_FAILED;
        lock_down_status.unlock();
        goto end;
    }

    ofmt = ofmt_ctx->oformat;

    for (i = 0; i < ifmt_ctx->nb_streams; i++) {
        AVStream* out_stream;
        AVStream* in_stream = ifmt_ctx->streams[i];
        AVCodecParameters* in_codecpar = in_stream->codecpar;

        if (in_codecpar->codec_type != AVMEDIA_TYPE_AUDIO &&
            in_codecpar->codec_type != AVMEDIA_TYPE_VIDEO &&
            in_codecpar->codec_type != AVMEDIA_TYPE_SUBTITLE) {
            stream_mapping[i] = -1;
            continue;
        }

        stream_mapping[i] = stream_index++;
        Downloads[param.index].percentage.push_back(0);
        last_dts.push_back(0);

        out_stream = avformat_new_stream(ofmt_ctx, NULL);
        if (!out_stream) {
            lock_down_status.lock();
            Downloads[param.index].err_msg = "Failed allocating output stream";
            Downloads[param.index].status = DOWNLOAD_FAILED;
            lock_down_status.unlock();
            ret = AVERROR_UNKNOWN;
            goto end;
        }

        ret = avcodec_parameters_copy(out_stream->codecpar, in_codecpar);
        if (ret < 0) {
            lock_down_status.lock();
            Downloads[param.index].err_msg = "Failed to copy codec parameters";
            Downloads[param.index].status = DOWNLOAD_FAILED;
            lock_down_status.unlock();
            goto end;
        }
        out_stream->codecpar->codec_tag = 0;
    }
    av_dump_format(ofmt_ctx, 0, out_filename, 1);

    if (!(ofmt->flags & AVFMT_NOFILE)) {
        ret = avio_open(&ofmt_ctx->pb, out_filename, AVIO_FLAG_WRITE);
        if (ret < 0) {
            lock_down_status.lock();
            Downloads[param.index].err_msg = "Could not open output file";
            Downloads[param.index].status = DOWNLOAD_FAILED;
            lock_down_status.unlock();
            goto end;
        }
    }

    ret = avformat_write_header(ofmt_ctx, NULL);
    if (ret < 0) {
        lock_down_status.lock();
        Downloads[param.index].err_msg = "Error occurred when opening output file";
        Downloads[param.index].status = DOWNLOAD_FAILED;
        lock_down_status.unlock();
        goto end;
    }

    while (Downloads[param.index].status != DOWNLOAD_CANCELLED) {
        AVStream* in_stream, * out_stream;

        ret = av_read_frame(ifmt_ctx, pkt);
        if (ret < 0)
            break;

        in_stream = ifmt_ctx->streams[pkt->stream_index];
        if (pkt->stream_index >= stream_mapping_size ||
            stream_mapping[pkt->stream_index] < 0) {
            av_packet_unref(pkt);
            continue;
        }

        pkt->stream_index = stream_mapping[pkt->stream_index];
        out_stream = ofmt_ctx->streams[pkt->stream_index];

        /* copy packet */
        av_packet_rescale_ts(pkt, in_stream->time_base, out_stream->time_base);
        pkt->pos = -1;
        if (pkt->dts <= last_dts[pkt->stream_index])
            continue;
        last_dts[pkt->stream_index] = pkt->dts;
        lock_down_status.lock();

        AVRational* time_base = &ifmt_ctx->streams[pkt->stream_index]->time_base;
        Downloads[param.index].percentage[pkt->stream_index] = 100.0
            * ((pkt->pts * av_q2d(*time_base) - ifmt_ctx->start_time / (double)AV_TIME_BASE))
            / (ifmt_ctx->duration / (double)AV_TIME_BASE);
        lock_down_status.unlock();

        ret = av_interleaved_write_frame(ofmt_ctx, pkt);
        /* pkt is now blank (av_interleaved_write_frame() takes ownership of
         * its contents and resets pkt), so that no unreferencing is necessary.
         * This would be different if one used av_write_frame(). */
        if (ret < 0) {
            lock_down_status.lock();
            Downloads[param.index].err_msg = "Error muxing packet";
            Downloads[param.index].status = DOWNLOAD_FAILED;
            lock_down_status.unlock();
            break;
        }
    }

    av_write_trailer(ofmt_ctx);
end:
    av_packet_free(&pkt);

    avformat_close_input(&ifmt_ctx);

    /* close output */
    if (ofmt_ctx && !(ofmt->flags & AVFMT_NOFILE))
        avio_closep(&ofmt_ctx->pb);
    avformat_free_context(ofmt_ctx);

    av_freep(&stream_mapping);

    if (ret < 0 && ret != AVERROR_EOF) {
        return 1;
    }
    lock_down_status.lock();
    if (Downloads[param.index].status == DOWNLOADING)
        Downloads[param.index].status = DOWNLOAD_SUCCEEDED;
    lock_down_status.unlock();
    return 0;
}

DWORD WINAPI RemuxStarter(LPVOID lParam)
{
    down_t_param tparam = new_down_args;
    start_down_thread_lock.release();
    down_param param;
    DownloadStatus status_new;
    regex slash("[\\\\/]+"), symbols_file("[<\\|>\\?\\*:\"/\\\\]");
    int ret_code;
    bool allow_download = true;

    status_new.path = tparam.path.find(":") != tparam.path.npos ?
        regex_replace(tparam.path, slash, "\\") :
        asc_utf8(pwd) + regex_replace(tparam.path, slash, "\\");
    status_new.filename = tparam.filename;
    status_new.fallback_filename = regex_replace(tparam.filename, symbols_file, "_");
    status_new.url = tparam.url;
    status_new.status = DOWNLOAD_WAITING;
    if (!EndsWith(status_new.path, "\\"))
        status_new.path += "\\";

    lock_down_status.lock();
    param.index = Downloads.size();
    Downloads.push_back(status_new);
    ret_code = SHCreateDirectory(NULL, utf8_w(Downloads[param.index].path).data());
    if (ret_code != ERROR_SUCCESS && ret_code != ERROR_ALREADY_EXISTS && ret_code != ERROR_FILE_EXISTS)
    {
        Downloads[param.index].status = DOWNLOAD_FAILED;
        Downloads[param.index].err_msg = "Failed to create folder: WinError ";
        Downloads[param.index].err_msg += to_string(ret_code);
        allow_download = false;
    }
    lock_down_status.unlock();

    if (allow_download)
    {
        download_lock.acquire();
        lock_down_status.lock();
        Downloads[param.index].fallback_filename = GetUniqueFilename(Downloads[param.index].path, Downloads[param.index].fallback_filename);
        Downloads[param.index].status = DOWNLOADING;
        param.infile = Downloads[param.index].url;
        param.outfile = Downloads[param.index].fallback_filename;
        cerr << "[" << param.index << "] Start downloading " << Downloads[param.index].url << " to directory \""
            << Downloads[param.index].path << "\" with file name \"" << Downloads[param.index].fallback_filename
            << "\"\n";
        lock_down_status.unlock();
        remux(param);
        lock_down_status.lock();
        if (Downloads[param.index].status != DOWNLOAD_SUCCEEDED &&
            Downloads[param.index].status != DOWNLOAD_FAILED &&
            Downloads[param.index].status != DOWNLOAD_CANCELLED)
        {
            Downloads[param.index].status = DOWNLOAD_FAILED;
            Downloads[param.index].err_msg = "Unknown error";
        }
        cerr << "[" << param.index << "] Download finished with code " << (int)Downloads[param.index].status
            << "; error message (if success, it's empty): \n    " << Downloads[param.index].err_msg << "\n";
        lock_down_status.unlock();
        download_lock.release();
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
        if (no_browser)
            Params.append(" --no-browser");
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

    size_t pwd_len = GetCurrentDirectoryA(0, NULL) + 2;
    pwd = (CHAR*)malloc(pwd_len * sizeof(CHAR));
    GetCurrentDirectoryA(pwd_len, pwd);
    string pwd_asc = pwd;
    if (!EndsWith(pwd_asc, "\\"))
        pwd_asc += "\\";
    cerr << "Program running at " << pwd_asc << "\n";

    DWORD tid;
    HANDLE tHandle;
    tHandle = CreateThread(NULL, 0, ScanThread, NULL, 0, &tid);
    if (!tHandle)
    {
        cerr << "Failed to start thread: " << GetLastError() << "\n";
        return 1;
    }
    CloseHandle(tHandle);

    Server svr;

    svr.Get("/", [](const Request& req, Response& res) {
        res.set_content(vec2str(GetResource(IDR_HTML1, RT_HTML)), "text/html");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/js/video.min.js", [](const Request& req, Response& res) {
        res.set_content(vec2str(GetResource(IDR_JS1, L"JS")), "text/javascript");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/js/videojs-http-streaming.min.js", [](const Request& req, Response& res) {
        res.set_content(vec2str(GetResource(IDR_JS2, L"JS")), "text/javascript");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/css/video-js.min.css", [](const Request& req, Response& res) {
        res.set_content(vec2str(GetResource(IDR_CSS1, L"CSS")), "text/css");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/css/style.min.css", [](const Request& req, Response& res) {
        res.set_content(vec2str(GetResource(IDR_CSS2, L"CSS")), "text/css");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/js/script.min.js", [](const Request& req, Response& res) {
        res.set_content(vec2str(GetResource(IDR_JS3, L"JS")), "text/javascript");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/get-urls", [](const Request& req, Response& res) {
        lock_url.lock();
        json res_json(ReplayUrls);
        lock_url.unlock();
        res.set_content(res_json.dump(), "text/json");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/get-titles", [](const Request& req, Response& res) {
        lock_url.lock();
        json res_json(url_title);
        lock_url.unlock();
        res.set_content(res_json.dump(), "text/json");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/scan", [](const Request& req, Response& res) {
        require_scan = true;
        res.set_content("success", "text/plain");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Post("/set-autoscan-delay", [](const Request& req, Response& res) {
        res.set_content("success", "text/plain");
        res.set_header("Cache-Control", "no-cache");
        json body = json::parse(req.body);
        if (!body.is_number())
            res.set_content("Invalid argument: body should be a single float number", "text/plain");
        else
        {
            double required_delay = body;
            if (required_delay < 1 || required_delay > 90)
                res.set_content("Invalid argument: delay should between 1 and 90", "text/plain");
            else
                wait_int = required_delay * 1000;
        }
        });

    svr.Get("/enable-autoscan", [](const Request& req, Response& res) {
        auto_scan = true;
        next_scan = GetTickCount64() - 1;
        res.set_content("success", "text/plain");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/disable-autoscan", [](const Request& req, Response& res) {
        auto_scan = false;
        res.set_content("success", "text/plain");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/get-status", [](const Request& req, Response& res) {
        json ret_json = "{}"_json;
        ret_json["autoscan"] = auto_scan;
        ret_json["wait_interval"] = (double)wait_int / 1000;
        res.set_content(ret_json.dump(), "text/json");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Post("/require-download", [](const Request& req, Response& res) {
        uint8_t success = 1;
        json body;
        try
        {
            body = json::parse(req.body, nullptr, true, true);
        }
        catch (exception e) {
            success = 2;
            goto end;
        }
        if (!body.is_object())
            success = 2;
        else
        {
            if ((!body.contains("path")) || (!body.contains("downloads")))
                success = 2;
            else
            {
                if (!body["downloads"].is_array())
                {
                    success = 2;
                    goto end;
                }
                for (int i = 0; i < body["downloads"].size(); i++)
                {
                    if (!body["downloads"][i].is_object())
                    {
                        success = 2;
                        goto end;
                    }
                    if ((!body["downloads"][i].contains("url")) || (!body["downloads"][i].contains("name")))
                    {
                        success = 2;
                        goto end;
                    }
                }
                string url, name;
                for (int i = 0; i < body["downloads"].size(); i++)
                {
                    if (!url_title.contains(body["downloads"][i]["url"]))
                    {
                        success = 3;
                        goto end;
                    }
                    HANDLE ltHandle;
                    new_down_args.filename = body["downloads"][i]["name"];
                    new_down_args.path = body["path"];
                    new_down_args.url = body["downloads"][i]["url"];
                    start_down_thread_lock.acquire();
                    ltHandle = CreateThread(NULL, 0, RemuxStarter, NULL, 0, NULL);
                    if (ltHandle)
                        CloseHandle(ltHandle);
                    else
                        start_down_thread_lock.release();
                }
            }
        }
    end:
        res.set_header("Cache-Control", "no-cache");
        if (success == 1)
            res.set_content("success", "text/plain");
        else if(success == 2)
            res.set_content("Invalid argument: format should be like {\"path\": ..., \"downloads\": [{\"url\": ..., \"name\": ...}, ...]}", "text/plain");
        else if(success == 3)
            res.set_content("Invalid argument: url not recognized", "text/plain");
        });

    svr.Delete("/cancel-download/(\\d+)", [&](const Request& req, Response& res) {
        string index_str = req.matches[1];
        stringstream ss;
        ss << index_str;
        uint64_t index;
        ss >> index;
        res.set_header("Cache-Control", "no-cache");
        if (index >= Downloads.size())
            res.set_content("request out of range", "text/plain");
        else if (Downloads[index].status == DOWNLOADING || Downloads[index].status == DOWNLOAD_WAITING)
        {
            Downloads[index].status = DOWNLOAD_CANCELLED;
            res.set_content("success", "text/plain");
        }
        });

    svr.Get("/download-status", [](const Request& req, Response& res) {
        json ret_json = "[]"_json;
        lock_down_status.lock();
        for (int i = 0; i < Downloads.size(); i++)
        {
            ret_json.push_back("{}"_json);
            ret_json[i]["url"] = Downloads[i].url;
            ret_json[i]["name"] = Downloads[i].fallback_filename;
            ret_json[i]["path"] = Downloads[i].path;
            ret_json[i]["status"] = Downloads[i].status;
            if (Downloads[i].status == DOWNLOAD_WAITING)
            {
                ret_json[i]["percent"] = 0.0;
                ret_json[i]["msg"] = "";
            }
            else if (Downloads[i].status == DOWNLOAD_SUCCEEDED)
            {
                ret_json[i]["percent"] = 100.0;
                ret_json[i]["msg"] = "";
            }
            else
            {
                double percentage = 0;
                for (int j = 0; j < Downloads[i].percentage.size(); j++)
                    percentage += Downloads[i].percentage[j];
                if (Downloads[i].percentage.size())
                    percentage /= Downloads[i].percentage.size();
                ret_json[i]["percent"] = percentage < 0 ? 0.0 : (percentage >= 100 ? 99.99 : percentage);
                if (Downloads[i].status != DOWNLOADING)
                    ret_json[i]["msg"] = Downloads[i].err_msg;
                else
                    ret_json[i]["msg"] = "";
            }
        }
        lock_down_status.unlock();
        res.set_content(ret_json.dump(), "text/json");
        res.set_header("Cache-Control", "no-cache");
        });

    svr.Get("/stop", [&](const Request& req, Response& res) {
        Running = false;
        svr.stop();
        });

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
    if (!no_browser)
    {
        ShellExecuteA(NULL, "open", url_open.data(), NULL, NULL, SW_SHOW);
    }

    cerr << "Visit " << url_open << " to operate\n";
    svr.listen(ip, port);

    return 0;
}