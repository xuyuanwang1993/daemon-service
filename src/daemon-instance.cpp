#include "daemon-instance.h"
#include "unix-socket-helper.h"
#include <sys/prctl.h>
#include <dirent.h>
#include<set>
#include<chrono>
#include<list>
#define DAEMON_SERVICE_VERSION "1.0.0"
#define DAEMON_CONFIG_FILE_EXAMPLE_NAME "daemonConfig.ini.default"
#define DAEMON_SESSION_CONFIG_FILE_EXAMPLE_NAME "app.conf.default"
#define DAEMON_ENV_CONFIG_FILE_EXAMPLE_NAME "envExample.env.default"
#define DAEMON_LOCAL_SERVICE_NAME "/tmp/daemon-service.service"
#define DAEMON_SHELL_TYPE "shellscript"
#define DAEMON_PROCESS_TYPE "process"
#define DAEMON_CONFIG_ITEM "daemon-config"
using namespace aimy;
Daemon *Daemon::m_workDaemon=nullptr;
std::string Daemon::m_binName="supervisord";
std::string Daemon::m_workPath="/userdata/aimy/bootstraps/daemon/conf.d";
std::string Daemon::m_logPath="/userdata/aimy/logs/daemon";
uint32_t Daemon::m_logFileSizeKBytesLimit=0;
bool Daemon::m_logToTerminal=false;
std::string Daemon::m_configFileName="/userdata/aimy/bootstraps/daemon/daemonConfig.ini";
int Daemon::m_statusPrintIntervalSec=0;
static const uint32_t max_path_size=108;
enum ConfigItemType:uint8_t
{
    CONFIG_CMD=0,
    CONFIG_AUTO_START,
    CONFIG_AUTO_RESTART,
    CONFIG_START_DELAY_SEC,
    CONFIG_RESTART_INTERVAL_SEC,
    CONFIG_ENV,
    CONFIG_WORK_PATH,
    CONFIG_LOG_PATH,
    CONFIG_LOG_FILE_SIZE_LIMIT_KB,
    CONFIG_LOG_TO_TERMINAL,
    CONFIG_STATUS_PRINT_INTERVAL_SEC,
    CONFIG_MAX_ERROR_REBOOT_CNT,
    CONFIG_ERROR_THRESHOLD,
    CONFIG_EXEC_TYPE,
    CONFIG_ITEM_TYPE_LENGTH,
};

static const char*ConfigItemString[64]=
{
    "command",
    "autostart",
    "autorestart",
    "startsecs",
    "restartsecs",
    "environment",
    "directory",
    "logPath",
    "logFileSizeKBytesLimit",
    "logToTerminal",
    "statusPrintIntervalSec",
    "maxErrorRebootCnt",
    "rebootErrorThresholdSec",
    "exectype"

};

static std::map<std::string,ConfigItemType>&getConfigItemMap()
{
    static std::map<std::string,ConfigItemType> itemMap;
    if(itemMap.empty())
    {
        itemMap.emplace("",CONFIG_ITEM_TYPE_LENGTH);
        for(uint8_t i=0;i<CONFIG_ITEM_TYPE_LENGTH;++i)
        {
            itemMap.emplace(ConfigItemString[i],static_cast<ConfigItemType>(i));
        }
    }
    return itemMap;
}

void Daemon::initDaemonCommonTask()
{
    AIMY_INFO("init daemon conmmon task");
    m_daemonWorker->start();
}

void Daemon::initDaemonSelfTask()
{
    AIMY_INFO("init daemon self task");
    auto ppid=getpid();
    std::thread t([this,ppid](){
        AIMY_INFO("self daemon task thread start!");
        while(m_working.load())
        {
            auto pid=fork();
            if(pid<0)
            {
                AIMY_ERROR("self daemon fork error[%s]",strerror(errno));
                std::this_thread::sleep_for(std::chrono::milliseconds(30));
                continue;
            }
            else if (pid==0) {
                umask(0);//
                chdir("/");
                checkWorkProcessTask(ppid);
            }
            else {
                AIMY_DEBUG("init self daemon process parent[%d] %d success",getpid(),pid);
                {
                    std::lock_guard<std::mutex>locker(m_mutex);
                    m_selfDaemonPid=pid;
                }
                //阻塞回收进程
                waitpid(pid,nullptr,0);
                AIMY_DEBUG("self daemon process[%d] exit[working->%d]!",pid,m_working.load());
                {
                    std::lock_guard<std::mutex>locker(m_mutex);
                    m_selfDaemonPid=0;
                }
            }
        }
        AIMY_INFO("self daemon task thread exit!");
    });
    t.detach();
}

void Daemon::mainEventLoop()
{
    AIMY_ERROR("daemon main event-loop enter!");
    do{
        unix_dgram_socket sock(DAEMON_LOCAL_SERVICE_NAME);
        auto fd=sock.build();
        if(fd<=0)
        {
            AIMY_ERROR("init daemon-service failed[%s]",strerror(errno));
            break;
        }
        static uint32_t max_len=32*1024;
        char buf[max_len];

        while(m_working.load())
        {
            memset(buf,0,max_len);
            auto ret=sock.recv(buf,max_len);
            if(ret<0)
            {
                AIMY_ERROR("daemon loop fata error[%s]",strerror(errno));
                break;
            }
            else if (static_cast<uint32_t>(ret)<=max_path_size) {
                continue;
            }
            else {
                std::string source_path(buf,max_path_size);
                AIMY_DEBUG("daemon recv from %s command:\"%s\"",source_path.c_str(),std::string(buf+max_path_size,ret-max_path_size).c_str());
                //parser
                std::string option1;
                std::string option2;
                bool find_space=false;
                uint32_t start_pos=max_path_size+1;
                while(start_pos<static_cast<uint32_t>(ret))
                {
                    if(buf[start_pos]=='\0')break;
                    else if (buf[start_pos]==' ') {
                        find_space=true;
                        break;
                    }
                    ++start_pos;
                }
                option1=std::string(buf+max_path_size,start_pos-max_path_size);
                if(find_space&&start_pos+1<static_cast<uint32_t>(ret))option2=std::string(buf+start_pos+1,ret-start_pos-1);
                std::string ret=handleOption(option1,option2);
                sock.send(ret.c_str(),ret.length(),source_path);
            }
        }
    }while(0);
    AIMY_ERROR("daemon main event-loop quit!");
}

void Daemon::checkWorkProcessTask(pid_t ppid)
{
    while(1)
    {
        if(getppid()!=ppid)
        {
            Daemon::initDaemon();
            break;
        }
        else {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

bool Daemon::initSigleInstanceLock(const std::string &processName)
{
    //
    bool ret=false;
    static const char *lockFileName="/tmp/daemon_service.lck";
    int fd=-1;
    do{
        fd=open(lockFileName,O_RDWR|O_CREAT|__O_CLOEXEC,S_IRUSR|S_IWUSR|S_IRGRP|S_IROTH);
        if(fd<=0)
        {
            AIMY_ERROR("open %s failed[%s]",lockFileName,strerror(errno));
            break;
        }
        AIMY_INFO("open %s success",lockFileName);
        int flags=LOCK_EX;;
        int iret=0;
        iret = flock(fd,flags);
        if(iret!=0)
        {
            AIMY_ERROR("%s is locking[%d->%s]",lockFileName,iret,strerror(errno));
            break;
        }
        AIMY_INFO("flock %s success",lockFileName);
        //check pid
        char buf[32]={0};
        memset(buf,0,32);
        auto len=read(fd,buf,31);
        bool isexisted=false;
        if(len>0)
        {
            auto work_pid=std::stoi(buf);
            AIMY_INFO("work_pid %d %s",work_pid,processName.c_str());
            memset(buf,0,32);
            sprintf(buf,"/proc/%d/stat",work_pid);
            FILE *fp=fopen(buf,"r");
            do{
                if(!fp)break;
                size_t file_size=500;//max size
                std::shared_ptr<char>cache(new char[file_size+1],std::default_delete<char[]>());
                memset(cache.get(),0,file_size+1);
                auto read_len=fread(cache.get(),1,file_size,fp);
                if(read_len<=1)break;
                int pid=0;
                char pro_name[256];
                AIMY_INFO("%s",cache.get());
                sscanf(cache.get(),"%d (%[^)]",&pid,pro_name);
                AIMY_INFO("%d %s",pid,pro_name);
                if(processName==pro_name)
                {
                    isexisted=true;
                }
            }while(0);
            if(fp)fclose(fp);
        }
        if(isexisted)
        {
            AIMY_ERROR("process %s is working!",processName.c_str());
            break;
        }
        //write pid
        FILE *fp=fopen(lockFileName,"w+");
        if(!fp)
        {
            AIMY_ERROR("open %s error[%s]!",lockFileName,strerror(errno));
            break;
        }
        fprintf(fp,"%d",getpid());
        fclose(fp);
        fsync(fp->_fileno);
        ret=true;
    }while(0);
    if(fd>0)
    {
        flock(fd,LOCK_UN);
        ::close(fd);
    }
    return ret;
}

bool Daemon::dumpConfig(const std::string &path)
{
    bool ret=false;
    FILE *fp=nullptr;
    do{
        if(path.empty())
        {
            AIMY_ERROR("%s invalid param",__func__);
            break;
        }
        fp=fopen(path.c_str(),"w+");
        if(!fp)
        {
            AIMY_ERROR("open %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendItemTofile(DAEMON_CONFIG_ITEM,"","this is a config file for daemon",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        //write config
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_WORK_PATH],m_workPath,"specify workPath",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_LOG_PATH],m_logPath,"specify logPath",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_LOG_FILE_SIZE_LIMIT_KB],std::to_string(m_logFileSizeKBytesLimit),"limit log_file size kb range[32k-2G],<=0 means no limit",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_LOG_TO_TERMINAL],std::to_string(m_logToTerminal?1:0),
                                                   "is set to 0 log will print to terminal otherwise not",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_STATUS_PRINT_INTERVAL_SEC],std::to_string(m_statusPrintIntervalSec?1:0),
                                                   "is set to 0 log will print to terminal otherwise not",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        ret=true;
    }while(0);
    if(fp)fclose(fp);
    return ret;
}

void Daemon::initDaemon()
{
    AimyLogger::Instance().processReset();
    auto pid=fork();
    if(pid<0)
    {
        fprintf(stderr,"init_process fork  error[%s]\r\n",strerror(errno));
    }
    else if (pid==0) {
        loadConfig();
        processInitLog("work-process",Daemon::m_logPath);
        AIMY_INFO("---------------start[%d]---------------",getppid());
        AIMY_INFO("compile_info:%s %s",__DATE__,__TIME__);
        //auto pgid=getpgrp();
        setsid();//分离进程组
        //killpg(pgid,SIGKILL);//关闭原进程组中所有进程
        umask(0);
        chdir("/");

        if(!initSigleInstanceLock(Daemon::m_binName))
        {
            AIMY_ERROR("daemon is running!");
            exit(-1);
            AIMY_ERROR("daemon is running 22!");
        }
        AIMY_INFO("daemon init start!");
        m_workDaemon=new Daemon;
        Instance().m_daemonWorker=new DaemonWorker(m_workPath);
        Instance().m_daemonWorker->setPrintIntervalSec(m_statusPrintIntervalSec);
        Instance().initDaemonCommonTask();
        Instance().initDaemonSelfTask();
        Instance().mainEventLoop();
        kill(0,SIGKILL);//关闭进程组中所有进程
    }
    else {
        printf("init_process success %d %d!\r\n",getpid(),pid);
    }
}

void Daemon::processInitLog(const std::string pro_name,const std::string&path)
{
    aimy::AimyLogger::register_custom_instance(aimy::AimyLogger::create());
    aimy::AimyLogger::Instance().set_log_path(path,pro_name);
    aimy::AimyLogger::Instance().set_log_to_std(m_logToTerminal);
    if(m_logFileSizeKBytesLimit>0)aimy::AimyLogger::Instance().set_log_file_size(m_logFileSizeKBytesLimit*1024);
    aimy::AimyLogger::Instance().register_handle();
}

void Daemon::generateDefaultConfig(const std::string&path)
{
    auto save_path=path;
    if(path.empty())save_path="./";
    dumpConfig(save_path+"/"+DAEMON_CONFIG_FILE_EXAMPLE_NAME);
}

void Daemon::generateTaskExampleConfig(const std::string&path)
{
    auto save_path=path;
    if(path.empty())save_path="./";
    DaemonSession session;
    session.envMap.emplace("aamDaemon",__DATE__);
    session.envMap.emplace("aamDaemonDouble",__DATE__);
    session.dumpConfig(save_path+"/"+DAEMON_SESSION_CONFIG_FILE_EXAMPLE_NAME);
}

std::string Daemon::handleOption(const std::string &option1,const std::string &option2)
{
    std::string ret="success";
    if(option1=="shutdown")
    {
        AIMY_WARNNING("exit daemon service by external command!");
        ret="exit daemon_service!";
        m_working.exchange(false);
        std::lock_guard<std::mutex>locker(m_mutex);
        if(m_selfDaemonPid>0)kill(m_selfDaemonPid,SIGKILL);
    }
    else if (option1=="status") {
        ret=m_daemonWorker->getStatus();
    }
    else if (option1=="start") {
        if(option2.empty())
        {
            ret="start option need a task name";
        }
        else {
            ret=m_daemonWorker->startTask(option2);
        }
    }
    else if (option1=="stop") {
        if(option2.empty())
        {
            ret="stop option need a task name";
        }
        else {
            ret=m_daemonWorker->cancelTask(option2);
        }
    }
    else if (option1=="restart") {
        if(option2.empty())
        {
            ret="restart option need a task name";
        }
        else {
            ret=m_daemonWorker->restartTask(option2);
        }
    }
    else if (option1=="reload") {
        if(option2.empty())
        {
            ret="reload option need a task name";
        }
        else {
            ret=m_daemonWorker->reloadTask(option2);
        }
    }
    else if (option1=="load") {
        if(option2.empty())
        {
            ret="load option need a config file";
        }
        else {
            ret=m_daemonWorker->loadPath(option2);
        }
    }
    else {
        ret=std::string("option ")+option1+" isn't supported!";
    }
    return ret;
}

void Daemon::handleCommandline(int argc ,char *argv[])
{
    static const char * helpInfo=
            "version:"
            DAEMON_SERVICE_VERSION "\n"
            __TIME__ " " __DATE__ "\n"
                                  "Usage:\n"
                                  "-c,--config<work_path>\tspecify the daemon service work_path[/userdata/aimy/bootstraps]\n"
                                  "-h,--help\tprint this page\n"
                                  "-g,--generate<target_path>\tgenerate default config file to target path\n"
                                  "ctl <option>[option ...]\tother control options\n"
                                  "\n----------ctl-options--------\n"
                                  "shutdown\texit daemon service\n"
                                  "status\tprint daemon status\n"
                                  "start<taskName>\tstart a task\n"
                                  "stop<taskName>\tstop a task\n"
                                  "restart<taskName>\trestart a task\n"
                                  "reload<taskName>\treload a task from the workpath's config file\n"
                                  "load<configfilePath>\tload a new task from the config file\n"
                                  "\n---------config-info--------\n"
                                  "${work_path}/.dameon-service.ini specify daemon-serivce's base config\n"
                                  "${work_path}/appName.conf define a task whose's taskName is \"appName\"\n"
                                  "you can specify app's runtime environment variables with a *.env file\n";
    //get bin name
    std::string cache=argv[0];
    auto pos=cache.find_last_of('/');
    //
    std::string binToolName;
    if(pos!=std::string::npos)
    {
        binToolName=cache.substr(pos+1);
    }
    else {
        binToolName=cache;
    }
    m_binName=binToolName;
    if(argc<=1)
    {
        Daemon::initDaemon();
    }
    else {
        std::string main_option=argv[1];
        int next_argv_read_pos=2;
        if(main_option=="-c"||main_option=="--config")
        {//run
            if(argc<=next_argv_read_pos)
            {
                fprintf(stderr,"miss config file\n");
                printf("%s",helpInfo);
                return;
            }
            char real_path[1024];
            memset(real_path,0,1024);
            realpath(argv[next_argv_read_pos],real_path);
            m_configFileName=real_path;
            Daemon::initDaemon();
        }
        else if (main_option=="ctl") {
            //ctl
            if(argc<=next_argv_read_pos)
            {
                fprintf(stderr,"miss clt option\n");
                printf("%s",helpInfo);
                return;
            }
            std::string cmd_data=argv[next_argv_read_pos];
            ++next_argv_read_pos;
            while(next_argv_read_pos<argc)
            {
                cmd_data+=" ";
                cmd_data+=argv[next_argv_read_pos];
                ++next_argv_read_pos;
            }
            //init socket
            std::string path=std::string("/tmp/daemon_client_")+std::to_string(getpid())+".service";
            unix_dgram_socket sock(path);
            auto fd=sock.build();
            if(fd<=0)
            {
                fprintf(stderr,"init unix socket %s failed[%s]\n",path.c_str(),strerror(errno));
                return;
            }
            //packet
            const static uint32_t buf_size=32*1024;
            std::shared_ptr<char>buf(new char[buf_size],std::default_delete<char[]>());
            memset(buf.get(),0,buf_size);
            memcpy(buf.get(),path.c_str(),path.size());
            memcpy(buf.get()+max_path_size,cmd_data.c_str(),cmd_data.size());
            auto send_len=sock.send(buf.get(),max_path_size+cmd_data.size(),DAEMON_LOCAL_SERVICE_NAME);
            if(static_cast<decltype (max_path_size+cmd_data.size())>(send_len)!=(max_path_size+cmd_data.size()))
            {
                fprintf(stderr,"unix socket send error[%s]\n",strerror(errno));
                return;
            }
            //wait answer
            memset(buf.get(),0,buf_size);
            auto recv_len=sock.recv(buf.get(),buf_size,5000);
            if(recv_len>0)
            {
                printf("%s\n",std::string(buf.get(),recv_len).c_str());
            }
            else {
                fprintf(stderr,"unix socket recv error[%s]\n",strerror(errno));
            }
        }
        else if (main_option=="-g"||main_option=="--generate") {
            std::string path="./";
            if(argc<=next_argv_read_pos)
            {
                fprintf(stderr,"miss target path\n");
                printf("%s",helpInfo);
                return;
            }
            path=argv[next_argv_read_pos];
            Daemon::generateDefaultConfig(path);
            Daemon::generateTaskExampleConfig(path);
        }
        else if (main_option=="-h"||main_option=="--help") {
            printf("%s",helpInfo);
        }
        else {
            fprintf(stderr,"invalide option \"%s\"",main_option.c_str());
            printf("%s",helpInfo);
        }
    }
}

void Daemon::loadConfig()
{
    do{
        if(m_configFileName.empty())
        {
            AIMY_ERROR("configFileName is empty!");
            break;
        }
        DaemonFileHelper parser;
        auto ret=parser.parser(m_configFileName);
        if(!ret)
        {
            AIMY_ERROR("%s load[%s] failed!",__func__,m_configFileName.c_str());
            break;
        }
        std::string item_name=DAEMON_CONFIG_ITEM;
        auto iter=parser.itemMap.find(item_name);
        if(iter==parser.itemMap.end())
        {
            AIMY_ERROR("%s load[%s] failed!",__func__,item_name.c_str());
            break;
        }
        auto items_map=iter->second.configMap;
        auto &config_map=getConfigItemMap();
        for(auto i:items_map)
        {
            auto iter=config_map.find(i.first);
            if(iter!=config_map.end())
            {
                switch (iter->second) {
                case CONFIG_WORK_PATH:
                    m_workPath=i.second;
                    break;
                case CONFIG_LOG_PATH:
                    m_logPath=i.second;
                    break;
                case CONFIG_LOG_FILE_SIZE_LIMIT_KB:
                    if(!i.second.empty())m_logFileSizeKBytesLimit=std::stoul(i.second);
                    break;
                case CONFIG_LOG_TO_TERMINAL:
                    if(!i.second.empty())m_logToTerminal=std::stoi(i.second)!=0;
                    break;
                case CONFIG_STATUS_PRINT_INTERVAL_SEC:
                    if(!i.second.empty())m_statusPrintIntervalSec=std::stoi(i.second);
                    break;
                default:
                    AIMY_WARNNING("%s=%s not supported!",i.first.c_str(),i.second.c_str());
                    break;
                }
            }
            else {
                AIMY_WARNNING("%s=%s not int configitem map!",i.first.c_str(),i.second.c_str());
            }
        }
        AIMY_INFO("load daemon_config:%s success!",m_configFileName.c_str());
        return;
    }while(0);
    AIMY_ERROR("try dump config  default file");
    dumpConfig(m_workPath+"/"+DAEMON_CONFIG_FILE_EXAMPLE_NAME);
}

DaemonWorker::DaemonWorker(const std::string&configPath):m_configPath(configPath),m_workThread(nullptr),m_bRunning(false),m_statusPrintIntervalSec(30),m_lastPrintSec(0)
{
    loadAllConfig();
}

void DaemonWorker::start()
{
    AIMY_INFO("start daemon worker");
    if(m_bRunning.load())
    {
        AIMY_WARNNING("daemon worker is running!");
    }
    else {
        m_bRunning.exchange(true);
        std::lock_guard<std::mutex>locker(m_threadMutex);
        m_workThread.reset(new std::thread([this](){
            this->threadTask();
        }));
    }
}

void DaemonWorker::stop()
{
    AIMY_INFO("stop daemon worker");
    if(m_bRunning.load())
    {
        m_bRunning.exchange(false);
        {//wakeup
            std::lock_guard<std::mutex>locker(m_dataMutex);
            m_cv.notify_all();
        }
        std::lock_guard<std::mutex>locker(m_threadMutex);
        if(m_workThread)
        {
            if(m_workThread->joinable())m_workThread->join();
            m_workThread.reset();
        }
    }
    AIMY_INFO("stop daemon worker finished!");
}

std::string DaemonWorker::reloadTask(const std::string &TaskName)
{
    AIMY_INFO("reload task:%s",TaskName.c_str());
    std::lock_guard<std::mutex>locker(m_dataMutex);
    auto iter=m_tasksMap.find(TaskName);
    if(iter!=m_tasksMap.end())
    {
        AIMY_INFO("remove old task:%s",TaskName.c_str());
        m_tasksMap.erase(iter);
    }
    std::shared_ptr<DaemonSession>session(new DaemonSession);
    bool ret=session->loadConfig(session->configFilePath);
    if(ret)
    {
        m_tasksMap.emplace(TaskName,session);
        m_cv.notify_one();
        return std::string("load ")+TaskName+" success";
    }
    else {
        return std::string("load ")+TaskName+" failed";
    }
}

std::string DaemonWorker::loadPath(const std::string&configPath)
{
    std::shared_ptr<DaemonSession>session(new DaemonSession);
    bool ret=session->loadConfig(configPath);
    std::string taskname=session->configName;
    if(ret)
    {
        auto iter=m_tasksMap.find(taskname);
        if(iter==m_tasksMap.end())
        {
            m_tasksMap.emplace(taskname,session);
            m_cv.notify_one();
            return std::string("load ")+taskname+" success";
        }

    }
    return std::string("load ")+taskname+" failed";
}

std::string DaemonWorker::restartTask(const std::string &TaskName)
{
    std::string ret=__func__;
    ret+=" "+TaskName;
    do{
        std::lock_guard<std::mutex>locker(m_dataMutex);
        auto iter=m_tasksMap.find(TaskName);
        if(iter==std::end(m_tasksMap))
        {
            ret+=" failed[no items]";
            break;
        }
        iter->second->restart();
        ret+=" success";
    }while(0);
    return ret;
}

std::string DaemonWorker::cancelTask(const std::string&TaskName)
{
    std::string ret=__func__;
    ret+=" "+TaskName;
    do{
        std::lock_guard<std::mutex>locker(m_dataMutex);
        auto iter=m_tasksMap.find(TaskName);
        if(iter==std::end(m_tasksMap))
        {
            ret+=" failed[no items]";
            break;
        }
        iter->second->stop();
        ret+=" success";
    }while(0);
    return ret;
}

std::string DaemonWorker::startTask(const std::string&TaskName)
{
    std::string ret=__func__;
    ret+=" "+TaskName;
    do{
        std::lock_guard<std::mutex>locker(m_dataMutex);
        auto iter=m_tasksMap.find(TaskName);
        if(iter==std::end(m_tasksMap))
        {
            ret+=" failed[no items]";
            break;
        }
        iter->second->start();
        ret+=" success";
    }while(0);
    return ret;
}


std::string DaemonWorker::getStatus()
{
    std::lock_guard<std::mutex>locker(m_dataMutex);
    if(m_tasksMap.empty())
    {
        return "no available task!";
    }
    else {
        return packetStatusString();
    }
}

DaemonWorker::~DaemonWorker()
{
    stop();
}

void DaemonWorker::threadTask()
{
    AIMY_INFO("daemon thread start!");
    std::unique_lock<std::mutex>locker(m_dataMutex);
    while(m_bRunning)
    {
        m_cv.wait_for(locker,std::chrono::milliseconds(100));
        //print status
        printTaskStatus();
        //check status
        for(auto i:m_tasksMap)
        {
            i.second->check();
        }
    }
    AIMY_WARNNING("daemon thread exit!");
}

void DaemonWorker::printTaskStatus()
{
    if(m_statusPrintIntervalSec<=0)return;
    timeval time_now;
    gettimeofday(&time_now,nullptr);
    if(time_now.tv_sec%m_statusPrintIntervalSec!=0||time_now.tv_sec==m_lastPrintSec)return;
    //record
    m_lastPrintSec=time_now.tv_sec;
    AIMY_INFO("-------------TASK_STATUS------------------");
    if(m_tasksMap.empty())
    {
        AIMY_WARNNING("no task");
    }
    else {

        AIMY_DEBUG("\n%s",packetStatusString().c_str());
    }
    AIMY_INFO("-------------TASK_STATUS_END------------------");
}

std::string DaemonWorker::packetStatusString()
{
    std::string ret;
    auto iter=m_tasksMap.begin();
    auto info=iter->second->getStatusString();
    ret=info.first+"\n";
    ret+=info.second;
    ++iter;
    while(iter!=m_tasksMap.end())
    {
        auto other_info=iter->second->getStatusString();
        ret+="\n";
        ret+=other_info.second;
        ++iter;
    }
    return ret;
}

void DaemonWorker::loadAllConfig()
{
    AIMY_INFO("load all config");
    //获取当前目录下所有以.conf结尾的文件名
    std::set<std::string> file_set;
    DIR *dir=nullptr;
    do{
        dir=opendir(m_configPath.c_str());
        if(!dir)break;
        struct dirent *ptr=nullptr;
        while((ptr=readdir(dir))!=nullptr)
        {
            if(ptr->d_name[0]==0)continue;
            if(ptr->d_type==DT_REG)file_set.insert(ptr->d_name);
        }
    }while(0);
    if(dir)closedir(dir);
    for(auto i:file_set)
    {
        //get suffix
        auto pos=i.find_last_of('.');
        if(pos==std::string::npos)continue;
        auto suffix=i.substr(pos);
        auto name=i.substr(0,pos);
        if(suffix==".conf")
        {
            AIMY_INFO("%s %s",name.c_str(),suffix.c_str());
            std::shared_ptr<DaemonSession>session(new DaemonSession);
            if(!session->loadConfig(m_configPath+"/"+i))continue;
            m_tasksMap.emplace(name,session);
        }
    }
    AIMY_WARNNING("----daemon_task print(%d)----",m_tasksMap.size());
    for(auto i:m_tasksMap)
    {
        AIMY_WARNNING("daemon_task:%s",i.first.c_str());
    }
}

void DaemonSession::start()
{

    if(status==DaemonSessionRunning)AIMY_WARNNING("%s is running!",configName.c_str());
    else {
        lastRebootCnt=0;
        status=DaemonSessionWaitStarted;
        nextBootTime=getTimetamp();
    }
}

void DaemonSession::restart()
{
    releaseProcess();
    start();
}

void DaemonSession::stop()
{
    releaseProcess();
}

void DaemonSession::check()
{
    do{
        if(status==DaemonSessionRunning)
        {//running
            //check exit
            auto ret=waitpid(pid,nullptr,WNOHANG);
            if(ret!=pid)break;
            resetBootStatus();
            AIMY_WARNNING("%s exited",configName.c_str());
            auto time_diff=getTimetamp()-lastBootTime;
            if(errorRebootThresholdSec>0&&time_diff<errorRebootThresholdSec)++errorBootCnt;
            else {
                errorBootCnt=0;
            }

            if(maxErrorRebootCnt>0&&errorBootCnt>=maxErrorRebootCnt)
            {
                errorBootCnt=0;
                status=DaemonSessionFatalError;
                AIMY_ERROR("%s run fatal error [%ld %ld]",configName.c_str(),errorRebootThresholdSec,maxErrorRebootCnt);
                break;
            }
            if(autoRestart)
            {
                AIMY_WARNNING("%s wait restart",configName.c_str());
                status=DaemonSessionWaitStarted;
                nextBootTime=getTimetamp()+restartIntervalSec;
            }
        }
    }while(0);
    if(status==DaemonSessionWaitStarted){
        //wait run
        auto now_time=getTimetamp();
        if(nextBootTime!=0&&now_time>=nextBootTime)
        {
            AIMY_DEBUG("try start %s",configName.c_str());
            auto new_pid=exec();
            ++bootCnt;
            ++lastRebootCnt;
            if(new_pid<=0)
            {
                AIMY_DEBUG("start %s failed,wait next turn!",configName.c_str());
                nextBootTime=now_time+restartIntervalSec;
            }
            else {
                AIMY_DEBUG("start %s success->pid[%d]!",configName.c_str(),new_pid);
                setRunningStatus(new_pid,now_time);
            }
        }
    }

}

bool DaemonSession::loadConfig(const std::string&path)
{//*.conf
    configFilePath=path;
    bool ret=false;
    do{
        if(path.empty())
        {
            AIMY_ERROR("%s invalid param!",__func__);
            break;
        }
        DaemonFileHelper parser;
        ret=parser.parser(path);
        if(!ret)
        {
            AIMY_ERROR("%s load[%s] failed!",__func__,path.c_str());
            break;
        }
        parser.dump();
        std::string item_name="program";
        auto iter=parser.itemMap.find(item_name);
        if(iter==parser.itemMap.end()||iter->second.description.empty())
        {
            AIMY_ERROR("%s load[%s:%s] failed!",__func__,item_name.c_str());
            break;
        }
        configName=iter->second.description;
        auto items_map=iter->second.configMap;
        auto &config_map=getConfigItemMap();
        for(auto i:items_map)
        {
            auto iter=config_map.find(i.first);
            if(iter!=config_map.end())
            {
                switch (iter->second) {
                case CONFIG_CMD:
                    execCmd=i.second;
                    break;
                case CONFIG_AUTO_START:
                    if(!i.second.empty())autoStart=i.second=="true";
                    break;
                case CONFIG_AUTO_RESTART:
                    if(!i.second.empty())autoRestart=i.second=="true";
                    break;
                case CONFIG_START_DELAY_SEC:
                    if(!i.second.empty())startDelaySec=std::stold(i.second);
                    if(startDelaySec<0)startDelaySec=0;
                    break;
                case CONFIG_RESTART_INTERVAL_SEC:
                    if(!i.second.empty())restartIntervalSec=std::stold(i.second);
                    if(restartIntervalSec<1)restartIntervalSec=1;
                    break;
                case CONFIG_MAX_ERROR_REBOOT_CNT:
                    if(!i.second.empty())maxErrorRebootCnt=std::stold(i.second);
                    break;
                case CONFIG_ERROR_THRESHOLD:
                    if(!i.second.empty())errorRebootThresholdSec=std::stold(i.second);
                    break;
                case CONFIG_ENV:
                    env=i.second;
                    envMap=parser.splitEnvInput(env);
                    break;
                case CONFIG_WORK_PATH:
                    workPath=i.second;
                    break;
                case CONFIG_EXEC_TYPE:
                    sessionType=i.second;
                    if(sessionType!=DAEMON_PROCESS_TYPE&&sessionType!=DAEMON_SHELL_TYPE)
                    {
                        sessionType=DAEMON_PROCESS_TYPE;
                    }
                    break;

                default:
                    AIMY_WARNNING("%s=%s not supported!",i.first.c_str(),i.second.c_str());
                    break;
                }
            }
            else {
                AIMY_WARNNING("%s=%s not int configitem map!",i.first.c_str(),i.second.c_str());
            }
        }

        if(autoStart)
        {
            status=DaemonSessionWaitStarted;
            nextBootTime=getTimetamp()+startDelaySec;
        }
        AIMY_INFO("load app_config:%s success!",path.c_str());
        ret=true;
    }while(0);
    return ret;
}

pid_t DaemonSession::exec()
{
    pid_t ret=0;
    do{
        auto cmd=execCmd;
        auto env_map=envMap;
        auto work_path=workPath;
        auto type=sessionType;
        AIMY_WARNNING("exec:%s",cmd.c_str());
        AIMY_WARNNING("workPath:%s",work_path.c_str());
        AIMY_WARNNING("type:%s",type.c_str());
        AIMY_WARNNING("ENV:%ld",env_map.size());

        for(auto i:env_map)
        {
            AIMY_WARNNING("%s=%s",i.first.c_str(),i.second.c_str());
        }
        ret=fork();
        if(ret<0)
        {
            AIMY_ERROR("fork error[%s]",strerror(errno));
            break;
        }
        else if (ret==0) {
            prctl(PR_SET_PDEATHSIG,SIGKILL);//设置父进程退出时向子进程发出kill信号,让子进程随父进程的退出而退出
            //setEnv
            for(auto i:env_map)
            {
                if(!i.first.empty())::setenv(i.first.c_str(),i.second.c_str(),1);
            }
            if(!work_path.empty())chdir(work_path.c_str());
            ::close(STDOUT_FILENO);//todo redirect stdout
            ::close(STDERR_FILENO);//todo redirect stderr
            //parser---
            if(type==DAEMON_SHELL_TYPE)
            {
                execl("/bin/sh", "sh", "-c", cmd.c_str(), (char *) 0);
            }
            else if (type==DAEMON_PROCESS_TYPE) {
                std::string pro_path;
                static const int max_length=50;
                char * argv[max_length];
                size_t argv_set_pos=0;
                size_t data_parser_pos=0;
                auto cmd_len=cmd.length();
                //dumplicate
                std::shared_ptr<char>tmp(new char[cmd_len+1],std::default_delete<char[]>());
                memset(tmp.get(),0,cmd_len+1);
                memcpy(tmp.get(),cmd.c_str(),cmd_len);
                //
                while(data_parser_pos<cmd_len&&(tmp.get()[data_parser_pos]==' '||tmp.get()[data_parser_pos]=='\0'))++data_parser_pos;
                while(data_parser_pos<cmd_len&&(argv_set_pos<max_length-1))
                {
                    //search end;
                    size_t search_begin=data_parser_pos+1;
                    while(search_begin<cmd_len&&tmp.get()[search_begin]!=' '&&tmp.get()[search_begin]!='\0')++search_begin;
                    //set argv
                    argv[argv_set_pos++]=tmp.get()+data_parser_pos;
                    tmp.get()[search_begin]='\0';
                    data_parser_pos=search_begin+1;
                    while(data_parser_pos<cmd_len&&(tmp.get()[data_parser_pos]==' '||tmp.get()[data_parser_pos]=='\0'))++data_parser_pos;
                }
                argv[argv_set_pos]=nullptr;
                if(argv_set_pos>0)pro_path=argv[0];
                if(!work_path.empty())chdir(work_path.c_str());
                if(!pro_path.empty())execv(pro_path.c_str(),argv);
            }
            _Exit(0);
        }
    }while(0);
    return ret;
}

void DaemonSession::releaseProcess()
{
    do{
        if(status!=DaemonSessionRunning)break;
        if(kill(pid,SIGKILL)==0)
        {
            int max_cnts=50;
            pid_t ret_pid=0;
            while((max_cnts-->0)&&(ret_pid=waitpid(pid,nullptr,WNOHANG))!=pid)std::this_thread::sleep_for(std::chrono::milliseconds(100));
            if(ret_pid==pid)
            {
                AIMY_WARNNING("%s exited in active",configName.c_str());
            }
            else {
                AIMY_WARNNING("%s exited failed",configName.c_str());
            }
        }
        else {
            AIMY_WARNNING("%s exited already",configName.c_str());
        }
    }while(0);
    resetBootStatus();
}

int64_t DaemonSession::getTimetamp()
{
    timeval now;
    gettimeofday(&now,nullptr);
    return static_cast<int64_t>(now.tv_sec);
}

void DaemonSession::resetBootStatus()
{
    AIMY_WARNNING("release %s %d",configName.c_str(),pid);
    status=DaemonSessionExited;
    pid=0;
    nextBootTime=0;
}

void DaemonSession::setRunningStatus(pid_t new_pid,int64_t boot_time)
{
    pid=new_pid;
    lastBootTime=boot_time;
    status=DaemonSessionRunning;
}

bool DaemonSession::dumpConfig(const std::string&path)
{
    bool ret=false;
    FILE *fp=nullptr;
    do{
        if(path.empty())
        {
            AIMY_ERROR("%s invalid param",__func__);
            break;
        }
        fp=fopen(path.c_str(),"w+");
        if(!fp)
        {
            AIMY_ERROR("open %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        const static char *info_str="this is a config file for daemon session,a valid session's config must end with \".conf\"\n"
                                    "#config support two exec type: \"process\" for normal program,\"shellscript\" for shell script";
        if(!DaemonFileHelper::appendItemTofile("program",configName,info_str,fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_CMD],execCmd,"exec command",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_EXEC_TYPE],sessionType,"exec type[shellscript/process]",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_AUTO_START],autoStart?"true":"false",
                                                   "if it's set to no zero value,it will be start after default loading",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_AUTO_RESTART],autoRestart?"true":"false",
                                                   "if it's set to no zero value,it will be restart after the task is done",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_START_DELAY_SEC],std::to_string(startDelaySec),
                                                   "specify the default start delay seconds",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_RESTART_INTERVAL_SEC],std::to_string(restartIntervalSec),
                                                   "specify the restart delay seconds",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_WORK_PATH],workPath,
                                                   "specify the work path",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_ERROR_THRESHOLD],std::to_string(errorRebootThresholdSec),
                                                   "specify the seconds threshold for an fatal reboot,<=0 will be inactive",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        if(!DaemonFileHelper::appendKeyValueTofile(ConfigItemString[CONFIG_MAX_ERROR_REBOOT_CNT],std::to_string(maxErrorRebootCnt),
                                                   "specify max fatal reboot cnts,<=0 will be inactive",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        std::list<std::string>envlist;
        for(auto &i:envMap)
        {
            envlist.push_back(i.first+"="+i.second);
        }
        if(!DaemonFileHelper::appendKeyValuelistTofile(ConfigItemString[CONFIG_ENV],envlist,
                                                   "specify the environment",fp))
        {
            AIMY_ERROR("write %s failed[%s]",path.c_str(),strerror(errno));
            break;
        }
        ret=true;
    }while(0);
    if(fp)fclose(fp);
    return ret;
}


std::pair<string, string> DaemonSession::getStatusString()
{
    char head_str[256]={0};
    memset(head_str,0,256);
    snprintf(head_str,sizeof (head_str),"%-16.16s\t%-12.12s\t%-12s\t%-21.21s%-12s%-12s","taskname","status","pid","lastBootTime","bootCnt","lastRebootCnt");
    auto status_str_func=[](DaemonSessionStatus status)->std::string{
        switch (status) {
        case DaemonSessionExited:
            return "exited";
        case DaemonSessionWaitStarted:
            return "waitStarted";
        case DaemonSessionRunning:
            return "running";
        case DaemonSessionFatalError:
            return "Fatal";
        }
        return "undefined";
    };
    time_t tt=lastBootTime;
    struct tm *t = localtime(&tt);
    char dateBuf[128];
    snprintf(dateBuf, sizeof(dateBuf), "%04d-%02d-%02d %02d:%02d:%02d", t->tm_year+1900,
             t->tm_mon+1, t->tm_mday, t->tm_hour, t->tm_min, t->tm_sec);

    char buf[256];
    memset(buf,0,256);
    sprintf(buf,"%-16.16s\t%-12.12s\t%-12d\t%-21.21s\t%-12d\t%-12d",configName.c_str(),status_str_func(status).c_str()
            ,pid,dateBuf,bootCnt,lastRebootCnt);
    return std::make_pair(std::string(head_str),std::string(buf));
}

DaemonSession::DaemonSession():sessionType(DAEMON_PROCESS_TYPE),execCmd(""),autoStart(false),autoRestart(true)
  ,startDelaySec(0),restartIntervalSec(5),workPath(""),env(""),maxErrorRebootCnt(0),
    errorRebootThresholdSec(0),pid(0),status(DaemonSessionExited)
  ,lastBootTime(0),nextBootTime(0),bootCnt(0),lastRebootCnt(0),errorBootCnt(0),configName("default"),configFilePath("")
{

}

DaemonSession::~DaemonSession()
{
    releaseProcess();
}

DaemonFileHelper::DaemonFileHelper():filePath("")
{

}

bool DaemonFileHelper::parser(const std::string &filePath)
{
    FILE *fp=nullptr;
    itemMap.clear();
    this->filePath=filePath;
    do{
        if(filePath.empty())
        {
            AIMY_ERROR("parser invalid param filePath!");
            break;
        }
        fp=fopen(filePath.c_str(),"r");
        if(!fp)
        {
            AIMY_ERROR("open file:%s failed[%s]",filePath.c_str(),strerror(errno));
            break;
        }
        char *buf=nullptr;
        size_t len=0;
        ssize_t nread=-1;
        uint32_t value_buf_len=128*1024;
        std::shared_ptr<char>value_buf(new char[value_buf_len+1],std::default_delete<char[]>());
        DaemonConfigInfo info;
        std::string data_cache;
        while(feof(fp)==0)
        {
            nread = getline(&buf, &len, fp);
            if(nread<=0||!buf)
            {
                continue;
            }
            auto data=trim(std::string(buf,nread));
            free(buf);
            buf=nullptr;

            //使用'#'做注释
            if(data[0]=='#'||data.empty())continue;
            if(data[0]=='[')
            {
                //handle cache
                if(data_cache.size()>=2)
                {
                    memset(value_buf.get(),0,value_buf_len+1);
                    char key[256]={0};
                    memset(key,0,256);
                    int ret=0;
                    if((ret=sscanf(data_cache.c_str(),"%[^=]=%[^\r\n]",key,value_buf.get()))!=2)
                    {
                        ret=sscanf(data_cache.c_str(),"%[^:]:%[^\r\n]",key,value_buf.get());
                    }
                    if(ret==2)info.configMap.emplace(trim(std::string(key)),trim(std::string(value_buf.get())));
                    else {

                        if((*data_cache.rbegin()==':')||(*data_cache.rbegin()=='='))
                        {
                            info.configMap.emplace(trim(data_cache.substr(0,data_cache.size()-1)),std::string());
                        }
                        else {
                            AIMY_WARNNING("file[%s] parse error->false format data[%s]!",filePath.c_str(),data_cache.c_str());
                        }
                    }
                    data_cache.clear();
                }
                if(!info.fieldName.empty()&&!info.configMap.empty())
                {
                    itemMap.emplace(trim(info.fieldName),info);
                    info.clear();
                }
                if(*data.rbegin()!=']'||data.size()<3)continue;
                int len=128;
                char description[len];
                memset(description,0,len);
                char type_str[len];
                memset(type_str,0,len);
                if(sscanf(data.c_str()+1,"%[^:]:%[^]]]",type_str,description)==2)
                {
                    info.fieldName=trim(type_str);
                    info.description=trim(description);
                }
                else{
                    info.fieldName=data.substr(1,data.size()-2);
                }
                AIMY_INFO("parse[%s] itemName:%s",filePath.c_str(),info.fieldName.c_str());
            }
            else {
                bool need_append=(*data.rbegin())=='\\';
                if(need_append)data_cache+=data.substr(0,data.size()-1);
                else {
                    data_cache+=data;
                    //handle cache
                    if(data_cache.size()>=2)
                    {
                        memset(value_buf.get(),0,value_buf_len+1);
                        char key[256]={0};
                        memset(key,0,256);
                        int ret=0;
                        if((ret=sscanf(data_cache.c_str(),"%[^=]=%[^\r\n]",key,value_buf.get()))!=2)
                        {
                            ret=sscanf(data_cache.c_str(),"%[^:]:%[^\r\n]",key,value_buf.get());
                        }
                        if(ret==2)info.configMap.emplace(trim(std::string(key)),trim(std::string(value_buf.get())));
                        else {

                            if((*data_cache.rbegin()==':')||(*data_cache.rbegin()=='='))
                            {
                                info.configMap.emplace(trim(data_cache.substr(0,data_cache.size()-1)),std::string());
                            }
                            else {
                                AIMY_WARNNING("file[%s] parse error->false format data[%s]!",filePath.c_str(),data_cache.c_str());
                            }
                        }
                        data_cache.clear();
                    }
                }
            }
        }
        //handle cache
        if(data_cache.size()>=2)
        {
            memset(value_buf.get(),0,value_buf_len+1);
            char key[256]={0};
            memset(key,0,256);
            int ret=0;
            if((ret=sscanf(data_cache.c_str(),"%[^=]=%[^\r\n]",key,value_buf.get()))!=2)
            {
                ret=sscanf(data_cache.c_str(),"%[^:]:%[^\r\n]",key,value_buf.get());
            }
            if(ret==2)info.configMap.emplace(trim(std::string(key)),trim(std::string(value_buf.get())));
            else {

                if((*data_cache.rbegin()==':')||(*data_cache.rbegin()=='='))
                {
                    info.configMap.emplace(trim(data_cache.substr(0,data_cache.size()-1)),std::string());
                }
                else {
                    AIMY_WARNNING("file[%s] parse error->false format data[%s]!",filePath.c_str(),data_cache.c_str());
                }
            }
            data_cache.clear();
        }
        if(!info.fieldName.empty()&&!info.configMap.empty())
        {
            itemMap.emplace(trim(info.fieldName),info);
            info.clear();
        }
        AIMY_DEBUG("read %s finished",filePath.c_str());
    }while(0);
    if(fp)fclose(fp);
    return !itemMap.empty();
}

void DaemonFileHelper::dump()
{
    AIMY_DEBUG("%s",filePath.c_str());
    for(auto i:itemMap)
    {
        AIMY_WARNNING("item:%s %s %lu",i.first.c_str(),i.second.description.c_str(),i.second.configMap.size());
        for(auto j:i.second.configMap)
        {
            AIMY_DEBUG("%s=%s",j.first.c_str(),j.second.c_str());
        }
    }
}

std::string DaemonFileHelper::trim(const std::string&src)
{
    if(src.empty())return src;
    uint32_t begin_pos=0;
    uint32_t end_pos=src.size()-1;
    while(begin_pos<=end_pos)
    {
        if(isTrimCharacter(src[begin_pos]))++begin_pos;
        else {
            break;
        }
    }
    while(end_pos>=begin_pos)
    {
        if(isTrimCharacter(src[end_pos]))--end_pos;
        else {
            break;
        }
    }
    if(begin_pos>end_pos)return std::string();
    return src.substr(begin_pos,end_pos-begin_pos+1);
}

bool DaemonFileHelper::isTrimCharacter(char c)
{
    return c==' '||c=='\t'||c=='\r'||c=='\n';
}

std::map<std::string,std::string> DaemonFileHelper::splitEnvInput(const std::string&src,char split_char)
{
    std::map<std::string,std::string>ret;
    std::list<std::string>cache;
    cache.push_back(std::string());
    for(uint32_t i=0;i<src.length();++i)
    {
        char opt_char=src[i];
        if(opt_char==split_char)
        {
            cache.push_back(std::string());
        }
        else {
            cache.rbegin()->push_back(opt_char);
        }
    }
    char key[512];
    char value[2048];
    for(auto & i:cache)
    {
        if(i.empty())continue;
        memset(key,0,512);
        memset(value,0,512);
        if(sscanf(i.c_str(),"%[^=]=%[^\r\n]",key,value)!=2)continue;
        ret.emplace(trim(std::string(key)),trim(std::string(value)));
    }
    return ret;
}
bool DaemonFileHelper::appendItemTofile(const std::string &item_name,const std::string &descritopn,const std::string &comment,FILE *fp)
{
    bool ret=false;
    do{
        if(item_name.empty()||!fp)break;
        if(!comment.empty())
        {
            if(fprintf(fp,"#%s\r\n",comment.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        if(descritopn.empty())
        {
            if(fprintf(fp,"[%s]\r\n",item_name.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        else {
            if(fprintf(fp,"[%s:%s]\r\n",item_name.c_str(),descritopn.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        ret=true;
    }while(0);
    return ret;
}

bool DaemonFileHelper::appendKeyValueTofile(const std::string &key, const std::string &value, const std::string &comment, FILE *fp)
{
    bool ret=false;
    do{
        if(key.empty()||!fp)break;
        if(!comment.empty())
        {
            if(fprintf(fp,"#%s\r\n",comment.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        if(value.empty())
        {
            if(fprintf(fp,"%s=\r\n",key.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        else {
            if(fprintf(fp,"%s=%s\r\n",key.c_str(),value.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        ret=true;
    }while(0);
    return ret;
}

bool DaemonFileHelper::appendKeyValuelistTofile(const std::string &key, std::list<std::string>valueList, const std::string &comment, FILE *fp)
{
    bool ret=false;
    do{
        if(key.empty()||!fp)break;
        if(!comment.empty())
        {
            if(fprintf(fp,"#%s\r\n",comment.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        if(valueList.empty())
        {
            if(fprintf(fp,"%s=\r\n",key.c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
        }
        else {
            auto iter=valueList.begin();
            if(fprintf(fp,"%s=%s,\\\r\n",key.c_str(),iter->c_str())<=0)
            {
                AIMY_ERROR("write failed[%s]",strerror(errno));
                break;
            }
            bool failed=false;
            ++iter;
            for(;iter!=valueList.end();++iter)
            {
                if(fprintf(fp,"%s,\\\r\n",iter->c_str())<=0)
                {
                    AIMY_ERROR("write failed[%s]",strerror(errno));
                    failed=true;
                    break;
                }
            }
            if(failed)break;
        }
        ret=true;
    }while(0);
    return ret;
}
