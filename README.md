# ClassIn Replay Download

A program to download ClassIn replay videos. 

This program uses advanced native API (required by [`httplib`](https://github.com/yhirose/cpp-httplib)), so can only be used on Windows 10 or greater. The program provides the users a web interface which uses the latest CSS grammar, so Google Chrome or Microsoft Edge 105 or greater is required to ensure the panel functions well. Mozilla Firefox or Safari is not supported. 

For more information about usage, please visit [**this article written by bilibili@ZhangHJ**](https://www.bilibili.com/read/cv22153816) （简体中文使用说明）

### Advanced usage

Open a terminal and add `--help` to see help message. 

### Build from source

This program requires a C++ compiler supports C++20 standard, or at least MSVC 16.9 (Visual Studio 2019). 

1. Download zip or clone this repository. 
2. Extract `libffmpeg.7z` in `ClassIn_Replay_Download` folder. 
3. Open `ClassIn_Replay_Download.sln` with Visual Studio. 
4. Build! 
5. If the compiler can't find `libavutil/timestamp.h` or `libavformat/avformat.h`, please manually add `../include` to your `include` folder. 