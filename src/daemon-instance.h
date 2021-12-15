#ifndef DAEMONINSTANCE_H
#define DAEMONINSTANCE_H
#include<cstdio>
#include<cstdlib>
#include<unistd.h>
#include<cstring>
#include <sys/file.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include<map>
#include<mutex>
#include<atomic>
#include<condition_variable>
#include<regex>
#include"network-log.h"
namespace aimy {
enum DaemonSessionStatus:uint8_t
{
    /**
     * 任务停止
     */
    DaemonSessionExited,
    /**
     * 等待启动
     */
    DaemonSessionWaitStarted,
    /**
     * 进程正在运行
     */
    DaemonSessionRunning,
    /**
     * 若程序连续启动三次运行时长都不超过30s，会进入此状态，将不会再自动重启
     */
    DaemonSessionFatalError,
};

class DaemonWorker;
struct DaemonSession;
class Daemon
{
public:
    /**
     * @brief Instance  获取当前进程的daemon实例
     */
    static Daemon &Instance(){
        if(m_workDaemon)return *m_workDaemon;
        static Daemon daemon;
        return daemon;
    }
    /**
     * @brief initDaemon daemon初始化入口
     */
    static void initDaemon();
    /**
     * @brief processInitLog 初始化log
     */
    static void processInitLog(const std::string pro_name,const std::string&path="/userdata/aimy/logs/daemon");
    /**
     * @brief generateDefaultConfig 生成默认的daemon配置
     */
    static void generateDefaultConfig(const std::string&path="./");
    /**
     * @brief generateTaskExampleConfig 生成默认的session配置
     */
    static void generateTaskExampleConfig(const std::string&path="./");
    /**
     * @brief handleCommandline 命令行输入处理
     */
    static void handleCommandline(int argc ,char *argv[]);
    /**
     * @brief loadConfig 加载配置
     * 读取工作目录
     * 读取log有关配置
     */
    static void loadConfig();
private:
    Daemon():m_selfDaemonPid(0),m_working(true),m_daemonWorker(nullptr){
    };
    ~Daemon(){}
    /**
     * @brief initDaemonCommonTask 处理守护其它进程的守护任务
     */
    void initDaemonCommonTask();
    /**
     * @brief initDaemonSelfTask 自守护初始化
     */
    void initDaemonSelfTask();
    /**
     * @brief mainEventLoop 主循环，用于接收外部控制
     */
    void mainEventLoop();
    /**
     * @brief checkWorkProcessTask 检查父进程是否发生变化
     */
    void checkWorkProcessTask(pid_t ppid);
    /**
     * @brief initSigleInstanceLock 进程单例锁初始化
     */
    static bool initSigleInstanceLock(const std::string &processName);
    static bool dumpConfig(const std::string &path);
    /**
     * @brief handleOption 处理外部输入
     */
    std::string handleOption(const std::string &option1,const std::string &option2);
private:
    /**
     * @brief m_workDaemon 当前进程daemon实例
     */
    static Daemon *m_workDaemon;
    /**
     * @brief m_binName daemon程序名
     */
    static std::string m_binName;
    /**
     * @brief m_workPath daemon工作目录
     */
    static std::string m_workPath;
    /**
     * @brief m_logPath log目录
     */
    static std::string m_logPath;
    /**
     * @brief m_logFileSizeKBytesLimit log大小限制
     */
    static uint32_t m_logFileSizeKBytesLimit;
    /**
     * @brief m_logToTerminal 是否输出到终端
     */
    static bool m_logToTerminal;
    /**
     * @brief m_configFileName 配置文件名
     */
    static std::string m_configFileName;
    /**
     * @brief m_statusPrintIntervalSec 守护进程状态打印间隔
     */
    static int m_statusPrintIntervalSec;
    std::mutex m_mutex;
    /**
     * @brief m_selfDaemonPid 守护自身的进程id，退出时需要先改变工作状态再将此进程杀死
     */
    pid_t m_selfDaemonPid;
    /**
     * @brief m_working 是否处于工作状态
     */
    std::atomic<bool> m_working;
    /**
     * @brief m_daemonWorker woker工作实例
     */
    DaemonWorker *m_daemonWorker;
};
/**
 * @brief The DaemonWorker class 处理其它进程的守护任务
 */
class DaemonWorker{
public:
    /**
     * @brief DaemonWorker
     * @param configPath 工作目录
     */
    DaemonWorker(const std::string&configPath);
    /**
     * @brief start 启动worker工作线程
     */
    void start();
    /**
     * @brief stop 停止work工作线程
     */
    void stop();
    /**
     * @brief reloadTask 重新加载某个任务
     */
    std::string reloadTask(const std::string &TaskName);
    /**
     * @brief restartTask 重启某个任务
     */
    std::string restartTask(const std::string &TaskName);
    /**
     * @brief cancelTask 停止某个任务
     */
    std::string cancelTask(const std::string&TaskName);
    /**
     * @brief startTask 启动某个任务
     */
    std::string startTask(const std::string&TaskName);
    /**
     * @brief getStatus 获取状态
     */
    std::string getStatus();
    void setPrintIntervalSec(int interval)
    {
        m_statusPrintIntervalSec=interval;
    }
    ~DaemonWorker();
private:
    void threadTask();
    /**
     * @brief printTaskStatus 输出所有任务的状态
     */
    void printTaskStatus();
    /**
     * @brief loadAllConfig 从配置目录中加载所有任务
     */
    void loadAllConfig();
    /**
     * @brief packetStatusString
     * @return
     */
    std::string packetStatusString();
private:
    std::condition_variable m_cv;
    const std::string m_configPath;
    std::mutex m_dataMutex;
    std::map<std::string,std::shared_ptr<DaemonSession>>m_tasksMap;
    std::mutex m_threadMutex;
    std::shared_ptr<std::thread> m_workThread;
    std::atomic<bool> m_bRunning;
    int m_statusPrintIntervalSec;
    int64_t m_lastPrintSec;
};
struct DaemonSession
{
    //read from config
    std::string sessionType;//任务类型 process or shellscript
    std::string execCmd;//执行命令
    bool autoStart;//自动启动
    bool autoRestart;//自动重新启动
    int64_t startDelayMsec;//初始启动延时
    int64_t restartIntervalMsec;//重新启动间隔
    std::string workPath;//工作路径
    std::string envPath;//环境变量路径
    std::map<std::string,std::string>envMap;//环境变量表
    int64_t maxErrorRebootCnt;//最大允许的错误启动次数
    int64_t errorRebootThresholdMsec;//错误启动判断阈值，当一个程序持续运行时间小于此值时判断为一次错误启动
    //runtime param
    pid_t pid;//当前进程id
    DaemonSessionStatus status;//任务状态
    int64_t lastBootTime;//上次启动时间
    int64_t nextBootTime;//下一次启动时间
    int bootCnt;//总启动次数
    int lastRebootCnt;//连续的重启次数
    int errorBootCnt;//连续的错误启动次数
    //set by loadConfig
    std::string configName;
    //启动程序，若程序已启动 不产生影响
    void start();
    //启动程序，若程序已启动，杀死原有进程重新启动
    void restart();
    //关闭程序
    void stop();
    //检查程序状态
    //check调用间隔引起僵尸进程的短暂出现，调用间隔不能太大
    void check();
    bool loadConfig(const std::string&path);
    bool dumpConfig(const std::string&path);
    bool dumpEnv(const std::string&path);
    //获取状态
    std::pair<std::string,std::string> getStatusString();
private:
    //运行程序
    pid_t exec();
    //回收进程
    void releaseProcess();
    //获取当前时间戳
    static int64_t getTimetamp();
    //重置进程状态，在进程回收时调用
    void resetBootStatus();
    //将进程设置成运行状态
    void setRunningStatus(pid_t new_pid,int64_t boot_time);
public:
    DaemonSession();
    ~DaemonSession();
};

struct DaemonFileParser
{
    DaemonFileParser();
    bool parser(const std::string &filePath);
    std::string filePath;
    std::string itemName;
    std::map<std::string,std::string>configMap;
    ~DaemonFileParser(){}
};
}

#endif // DAEMONINSTANCE_H
