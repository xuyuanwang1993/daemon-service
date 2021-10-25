#include "network-log.h"
#include <iomanip>
#include <chrono>
#include<memory>
#include<sstream>
#include<iostream>
#include<string.h>
#include<cstdio>
#include<cstdlib>
#include<features.h>
#include<signal.h>
#include<list>
#if defined(__linux) || defined(__linux__)
#include <sys/stat.h>
#include<unistd.h>
#include <execinfo.h>
#include<cxxabi.h>
#include <sys/prctl.h>
#include <dirent.h>
#elif defined(WIN32) || defined(_WIN32)
#include <Windows.h>
#include<io.h>
#endif

using namespace aimy;
constexpr static char log_strings[][20]={
    "D",
    "I",
    "W",
    "E",
    "F",
    "B",
    "BT",
};
#if defined(__linux) || defined(__linux__)
#define PRINT_NONE               "\033[m"
#define PRINT_RED                "\033[0;32;31m"
#define PRINT_LIGHT_RED          "\033[1;31m"
#define PRINT_GREEN              "\033[0;32;32m"
#define PRINT_BLUE               "\033[0;32;34m"
#define PRINT_YELLOW             "\033[1;33m"
#define PRINT_BROWN              "\033[0;33m"
#define PRINT_PURPLE             "\033[0;35m"
#define PRINT_CYAN               "\033[0;36m"
#define PRINT_WHITE               "\033[0;37m"
constexpr static char log_color[][20] = {
    PRINT_NONE,
    PRINT_WHITE,
    PRINT_GREEN,
    PRINT_YELLOW,
    PRINT_RED,
    PRINT_LIGHT_RED,
    PRINT_PURPLE,
    PRINT_BLUE,
};
#elif defined(WIN32) || defined(_WIN32)
#define FOREGROUND_BLUE      0x0001 // text color contains blue.
#define FOREGROUND_GREEN     0x0002 // text color contains green.
#define FOREGROUND_CYAN     0x0003
#define FOREGROUND_RED       0x0004 // text color contains red.
#define FOREGROUND_PURPLE	0x0005
#define FOREGROUND_YELLOW	0x0006
#define FOREGROUND_NONE	0x0007
constexpr static int log_color[] = {
    FOREGROUND_NONE,
    FOREGROUND_NONE,
    FOREGROUND_GREEN,
    FOREGROUND_YELLOW,
    FOREGROUND_CYAN,
    FOREGROUND_RED,
    FOREGROUND_PURPLE,
    FOREGROUND_BLUE,
};
#endif
void signal_exit_func(int signal_num){
    //输出退出时调用栈
    aimy::AimyLogger::Instance().print_backtrace();
    if(aimy::AimyLogger::m_signal_catch_flag)
    {
        //输出退出时调用栈
        AIMY_LOG(LOG_FATALERROR,"program exit failured!");
        _Exit(EXIT_FAILURE);
    }
    AIMY_LOG(LOG_BACKTRACE,"recv signal %d",signal_num);
    switch (signal_num) {
    case SIGILL:
        std::cout<<"recv signal SIGILL\r\n";
        break;
    case SIGINT:
        std::cout<<"recv signal SIGINT\r\n";
        break;
    case SIGABRT:
        std::cout<<"recv signal SIGABRT\r\n";
        break;
    case SIGQUIT:
        std::cout<<"recv signal SIGQUIT\r\n";
        break;
    case SIGTERM:
        std::cout<<"recv signal SIGTERM\r\n";
        break;
    case SIGSTOP:
        std::cout<<"recv signal SIGSTOP\r\n";
        break;
    case SIGTSTP:
        std::cout<<"recv signal SIGTSTP\r\n";
        break;
    case SIGSEGV:
        std::cout<<"recv signal SIGSEGV\r\n";
        break;
    case SIGHUP:
        std::cout<<"recv signal SIGHUP\r\n";
        break;
    default:
        std::cout<<"recv signal "<<signal_num<<"\r\n";
        break;
    }
    if(aimy::AimyLogger::m_exit_func)aimy::AimyLogger::m_exit_func();
    aimy::AimyLogger::m_signal_catch_flag.exchange(true);
}
AimyLogger *AimyLogger::m_custom_instance=nullptr;
string AimyLogger::get_local_time(){
    static mutex time_mutex;
    lock_guard<mutex>locker(time_mutex);
    std::ostringstream stream;
    auto now = chrono::system_clock::now();
    time_t tt = chrono::system_clock::to_time_t(now);

#if defined(WIN32) || defined(_WIN32)
    struct tm tm;
    localtime_s(&tm, &tt);
    stream << std::put_time(&tm, "%F %T");
#elif  defined(__linux) || defined(__linux__)
    char buffer[200] = {0};
    std::string timeString;
    std::strftime(buffer, 200, "%FT%H:%M:%S", std::localtime(&tt));
    stream << buffer;
#endif
    return stream.str();
}

string AimyLogger::get_local_day()
{
    static mutex time_mutex;
    lock_guard<mutex>locker(time_mutex);
    std::ostringstream stream;
    auto now = chrono::system_clock::now();
    time_t tt = chrono::system_clock::to_time_t(now);

#if defined(WIN32) || defined(_WIN32)
    struct tm tm;
    localtime_s(&tm, &tt);
    stream << std::put_time(&tm, "%F %T");
#elif  defined(__linux) || defined(__linux__)
    char buffer[200] = {0};
    std::string timeString;
    std::strftime(buffer, 200, "%F", std::localtime(&tt));
    stream << buffer;
#endif
    return stream.str();
}

function<void()>AimyLogger::m_exit_func(nullptr);
atomic_bool AimyLogger::m_signal_catch_flag(false);
void AimyLogger::register_exit_signal_func(function<void()>exit_func)
{
    m_exit_func=exit_func;
    signal(SIGILL,signal_exit_func);
    signal(SIGINT,signal_exit_func);
    signal(SIGABRT,signal_exit_func);
    signal(SIGQUIT,signal_exit_func);
    signal(SIGTERM,signal_exit_func);
    signal(SIGSTOP,signal_exit_func);
    signal(SIGTSTP,signal_exit_func);
    signal(SIGSEGV,signal_exit_func);
    signal(SIGHUP,signal_exit_func);
}
void AimyLogger::log(int level,const char *file,const char *func,int line,const char *fmt,...){
    //小于最小打印等级的log不处理
    if(level<m_level||level>LOG_BACKTRACE)return;
    shared_ptr<char>buf(new char[MAX_LOG_MESSAGE_SIZE+1],std::default_delete<char[]>());
    buf.get()[MAX_LOG_MESSAGE_SIZE]='\0';
    int info_len=0;
    {
        (void)(file);
        (void)func;
        (void)line;
        auto time_str=get_local_time();
        info_len=snprintf(buf.get(),MAX_LOG_MESSAGE_SIZE,"[%s][%s]",time_str.c_str(),log_strings[level]);
        va_list arg;
        va_start(arg, fmt);
        vsnprintf(buf.get() + info_len, MAX_LOG_MESSAGE_SIZE - info_len, fmt, arg);
        va_end(arg);
#if defined(DEBUG)|| 1
        if(m_log_to_std){
            /*输出到标准输出*/
#if defined(__linux) || defined(__linux__)
            if(level<LOG_ERROR)fprintf(stdout,"%s%s%s%s",log_color[level+1],buf.get(),LINE_END,log_color[0]);
            else fprintf(stderr,"%s%s%s%s",log_color[level+1],buf.get(),LINE_END,log_color[0]);
#elif defined(WIN32) || defined(_WIN32)
            if (level < LOG_ERROR) {
                HANDLE handle = GetStdHandle(STD_OUTPUT_HANDLE);
                SetConsoleTextAttribute(handle, log_color[level+1]);
                fprintf(stdout, "%s%s",  buf.get(), LINE_END);
                SetConsoleTextAttribute(handle, FOREGROUND_INTENSITY|log_color[0]);
            }
            else {
                HANDLE handle = GetStdHandle(STD_ERROR_HANDLE);
                SetConsoleTextAttribute(handle, log_color[level+1]);
                fprintf(stderr, "%s%s", buf.get(), LINE_END);
                SetConsoleTextAttribute(handle, log_color[0]);
            }
#endif
        }
#endif
    }
    //若进程发生了变化，不再向文件中输出log
    if(!isValid()||!get_register_status())return;
    if(m_log_callback)
    {
        m_log_callback(std::string(buf.get()+info_len));
    }
    std::unique_lock<mutex> locker(m_mutex);
    if(!m_env_set)return;
    if(m_log_buf.size()<MAX_LOG_QUEUE_SIZE)m_log_buf.push(make_shared<string>(buf.get()));
    m_conn.notify_all();

}
bool AimyLogger::set_log_path(const string &path,const string &proname){
    if(!isValid())return false;
    std::lock_guard<mutex> locker(m_mutex);
    if(m_fp){
        fclose(m_fp);
        m_fp=nullptr;
    }
    if(m_clear_flag)reset_file();
    m_env_set=false;
    m_save_path=path;
    m_pro_name=proname;
    check_log_path();
#if defined(__linux) || defined(__linux__)
    if (m_save_path.empty()) {
        m_save_path = ".";
        m_save_path += DIR_DIVISION;
    }
    else mkdir(m_save_path.c_str(), 0777);
    if (access(m_save_path.c_str(), F_OK | W_OK) != -1)m_env_set = true;
#elif defined(WIN32) || defined(_WIN32)
    m_env_set = true;
    if (m_save_path.empty()) {
        m_save_path = ".";
        m_save_path += DIR_DIVISION;
    }
    else if( CreateDirectory(m_save_path.c_str(), nullptr)!=0)m_env_set=false;
#endif
    return m_env_set;
}
void AimyLogger::set_minimum_log_level(int level){

    if(level<LOG_DEBUG)m_level.exchange(LOG_DEBUG);
    else if(level>LOG_FATALERROR)m_level.exchange(LOG_FATALERROR);
    else {
        m_level.exchange(level);
    }
}

void AimyLogger::set_clear_flag(bool clear)
{
    if(!isValid())return;
    lock_guard<mutex> locker(m_mutex);
    m_clear_flag=clear;
}
void AimyLogger::set_log_file_size(long size)
{
    if(!isValid())return;
    lock_guard<mutex> locker(m_mutex);
    m_max_file_size=size;
    if(m_max_file_size<MIN_LOG_FILE_SIZE)m_max_file_size=MIN_LOG_FILE_SIZE;
    else if(m_max_file_size>MAX_LOG_FILE_SIZE)m_max_file_size=MAX_LOG_FILE_SIZE;
}
AimyLogger::AimyLogger():m_ppid(getppid()),m_registered(false),m_stop(false),m_fp(nullptr),m_last_filename(""),m_save_path(string(".")+DIR_DIVISION),m_env_set(false),m_level(MIN_LOG_LEVEL),m_clear_flag(false)\
  ,m_max_file_size(MIN_LOG_FILE_SIZE),m_log_callback(nullptr),m_write_error_cnt(0),m_log_to_std(true),m_log_file_cache_days(MIN_LOG_CLEAR_DAYS_DIFF),m_log_file_cache_ignore_days(MAX_LOG_CLEAR_DAYS_DIFF)
{

}
void AimyLogger::register_handle()
{
    if(!isValid())return;
    if(!get_register_status()){
        m_registered.exchange(true);
        m_stop.exchange(false);
        unique_lock<mutex>locker(m_mutex);
        m_thread.reset(new thread(&AimyLogger::run,this));
    }
}
void AimyLogger::unregister_handle()
{
    if(!isValid())return;
    m_stop.exchange(true);
    {
        unique_lock<mutex>locker(m_mutex);
        m_conn.notify_all();
    }
    if(m_thread&&m_thread->joinable())m_thread->join();
    m_thread.reset();
    m_registered.exchange(false);
}
AimyLogger::~AimyLogger(){
    if(get_register_status())unregister_handle();
}
bool AimyLogger::open_file()
{
    if(!m_env_set||m_save_path.empty())return false;
    auto time_string=get_local_day();
    string file_name=m_save_path+DIR_DIVISION+time_string+"-"+m_pro_name+".log";
    do{
        //check file_name;
        if(file_name!=m_last_filename)
        {
            m_last_filename=file_name;
            break;
        }
        //check fp
        if(!m_fp)break;
        //check file_size
        auto len=ftell(m_fp);
        if(len>m_max_file_size)break;
        return true;
    }while(0);
    if(m_fp){
        fclose(m_fp);
        m_fp=nullptr;
    }
    if(m_clear_flag)reset_file();
    check_log_path();
    m_fp=fopen(file_name.c_str(),"a+");
    return m_fp!=nullptr;
}
bool AimyLogger::append_to_file(const string & log_message)
{
    bool ret=true;
    do{
        auto ret=fwrite(log_message.c_str(),1,log_message.size(),m_fp);
        fflush(m_fp);
        if(ret<log_message.size())ret=false;
    }while(0);
    return ret;
}
void AimyLogger::run(){
    std::unique_lock<mutex> locker(m_mutex);
    while(!m_stop){
        if(m_log_buf.empty())m_conn.wait_for(locker,std::chrono::milliseconds(WAIT_TIME));
        if(m_log_buf.empty())continue;
        while(!m_log_buf.empty()){
            auto log_info=*m_log_buf.front()+LINE_END;
            {/*存至文件*/
                if(!open_file()||!append_to_file(log_info))m_write_error_cnt++;
                if(m_write_error_cnt>MAX_WRITE_ERROR_TRY&&m_env_set)reset_file();
            }
            m_log_buf.pop();
        }
    }
    if(m_fp){
        fclose(m_fp);
        m_fp=nullptr;
    }
}

bool AimyLogger::isValid()
{
    return m_ppid==getppid();
}

void AimyLogger::set_log_callback(const MAX_LOG_CACHE_CALLBACK &callback)
{
    m_log_callback=callback;
}

void AimyLogger::set_log_to_std(bool flag)
{
    m_log_to_std.exchange(flag);
}

void AimyLogger::reset_file(){
    if(m_fp){
        fclose(m_fp);
        m_fp=nullptr;
    }
    m_write_error_cnt = 0;
    string file_name = m_save_path;
    if (!m_save_path.empty())file_name += DIR_DIVISION;
    file_name += "*.log";
#if defined(__linux) || defined(__linux__)
    string cmd = "rm -rf ";
    cmd += file_name;
#elif defined(WIN32) || defined(_WIN32)
    string cmd = "del ";
    cmd += file_name;
#endif
    system(cmd.c_str());
}

void AimyLogger::check_log_path()
{
    auto get_day_func=[](const char *data)->int
    {
      char year[32];
      char mon[32];
      char day[32];
      memset(year,0,32);
      memset(mon,0,32);
      memset(day,0,32);
      int ret=0;
      if(data&&sscanf(data,"%[^-]-%[^-]-%[^-]",year,mon,day)==3)
      {
          ret=std::stoi(year)*12*30+std::stoi(mon)*24+std::stoi(day);
      }
      return ret;
    };

#if defined(__linux) || defined(__linux__)
    std::list<std::string>removeList;
    auto local_day=get_day_func(get_local_day().c_str());
    DIR *dir=nullptr;
    do{
        dir=opendir(m_save_path.c_str());
        if(!dir)break;
        struct dirent *ptr=nullptr;
        while((ptr=readdir(dir))!=nullptr)
        {
            if(ptr->d_name[0]==0)continue;
            if(ptr->d_type==DT_REG)
            {
                auto file_day=get_day_func(ptr->d_name);
                auto day_diff=std::abs(local_day-file_day);
                if(day_diff>m_log_file_cache_days&&day_diff<m_log_file_cache_ignore_days)
                {
                    removeList.push_back(m_save_path+"/"+ptr->d_name);
                }
            }
        }
    }while(0);
    if(dir)closedir(dir);
    for(auto i:removeList)
    {
        remove(i.c_str());
    }
#elif defined(WIN32) || defined(_WIN32)

#endif
}

void AimyLogger::print_backtrace(int dumpSize)
{
#if defined(__linux) || defined(__linux__)
    //输出程序的绝对路径
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    auto count = readlink("/proc/self/exe", buffer, sizeof(buffer));
    if(count > 0){
        buffer[count] = 0;
        AIMY_LOG(LOG_BACKTRACE,"%s",buffer);
    }
    time_t tSetTime;
    time(&tSetTime);
    struct tm* ptm = localtime(&tSetTime);
    //输出信息的时间
    memset(buffer, 0, sizeof(buffer));
    sprintf(buffer, "Dump Time: %d-%d-%d %d:%d:%d",
            ptm->tm_year+1900, ptm->tm_mon+1, ptm->tm_mday,
            ptm->tm_hour, ptm->tm_min, ptm->tm_sec);
    AIMY_LOG(LOG_BACKTRACE,"%s",buffer);


    //堆栈
    void**DumpArray=new void*[dumpSize+2];
    int    nSize =    backtrace(DumpArray, dumpSize+2);
    sprintf(buffer, " backtrace rank = %d", nSize);
    AIMY_LOG(LOG_BACKTRACE,"%s",buffer);
    if (nSize > 0){
        char** symbols = backtrace_symbols(DumpArray, nSize);
        if (symbols != nullptr){
            for (int i=2; i<nSize; i++){
                std::string base(symbols[i]);
                printf("%s\r\n",symbols[i]);
                base=abi_convert(base);
                sprintf(buffer, "%d:%s", i-2,base.c_str());
                AIMY_LOG(LOG_BACKTRACE,"%s",buffer);
            }
            free(symbols);
        }
    }
    delete []DumpArray;
#endif
}

string AimyLogger::abi_convert(const std::string &input)
{
    std::list<std::string> splitList;
    std::string ret=input;
#if defined(__linux) || defined(__linux__)
    auto convert_func=[](const char *name)->std::string{
        std::string ret;
        int status=0;
        auto ret_temp=abi::__cxa_demangle(name,nullptr,nullptr,&status);
        if(status==0){
            ret=ret_temp;
        }
        free(ret_temp);
        return  ret;
    };
    auto index1=input.find_last_of('(');
    auto index2=input.find_last_of('+');
    auto index3=input.find_last_of(')');
    do{
        if(index1==std::string::npos||index3==std::string::npos||index2==std::string::npos)break;
        {
            splitList.push_back(input.substr(0,index1+1));
            auto len=index2-index1;
            if(len>0)
            {
                auto splitSlice=input.substr(index1+1,len);
                auto trueName=convert_func(splitSlice.c_str());
                if(trueName.empty())splitList.push_back(splitSlice);
                else {
                    splitList.push_back(trueName);
                }
            }
         }
        splitList.push_back("+");
        int len=index3-index2;
        if(len>0)
        {
            auto splitSlice=input.substr(index2+1,len);
            auto trueName=convert_func(splitSlice.c_str());
            if(trueName.empty())splitList.push_back(splitSlice);
            else {
                splitList.push_back(trueName);
            }
        }
        if(index3<input.size())
        {
            splitList.push_back(input.substr(index3));
        }
        ret.clear();
        for(auto i:splitList)
        {
            ret+=i;
        }
    }while(0);
#endif
    return ret;
}
