#include <iostream>
#include "daemon-instance.h"
#include<random>
using namespace aimy;

void session_test(char *argv[])
{

    DaemonSession session;
    session.loadConfig(argv[1]);
    std::random_device rd;
    int chance_cnt=10;
    while(1)
    {
        session.check();
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        while(chance_cnt--<=0)
        {
            int operation=rd()%3;
            AIMY_WARNNING("operartion %d",operation);
            if(operation==0)session.start();
            else if (operation==1) {
                session.restart();
            }
            else {
                session.stop();
            }
            chance_cnt=10;
        }
        auto ret=session.getStatusString();
    }
}
void worker_test(char *argv[])
{
     DaemonWorker WOER(argv[1]);
     WOER.start();
    std::random_device rd;
    int chance_cnt=10;
    while(1)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
        while(chance_cnt--<=0)
        {
            int operation=rd()%4;
            AIMY_WARNNING("operartion %d",operation);
            if(operation==0)WOER.startTask("app");
            else if (operation==1) {
                WOER.restartTask("app");
            }
            else if (operation==2) {
                WOER.reloadTask("app");
            }
            else {
                WOER.cancelTask("app");

            }
            AIMY_WARNNING("operartion %d end",operation);
            chance_cnt=10;
        }
    }
}

int main(int argc ,char *argv[])
{
//    AimyLogger::Instance().register_handle();
//    AimyLogger::Instance().set_log_to_std(true);
//    DaemonFileHelper parser;
//    parser.parser(argv[1]);
//    parser.dump();
//    auto config_map=parser.itemMap["program"].configMap;
//    auto env_map=parser.splitEnvInput(config_map["environment"]);
//    for(auto i:env_map)
//    {
//        AIMY_DEBUG("%s = %s",i.first.c_str(),i.second.c_str());
//    }
//    return 0;
    Daemon::handleCommandline(argc,argv);
    return 0;
}
