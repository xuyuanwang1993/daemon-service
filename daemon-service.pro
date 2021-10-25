TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt
TARGET = daemon-service
include(./daemon-service-include.pri)
include(./platform-config-common.pri)



HEADERS+= ./src/daemon-instance.h \
        ./src/network-log.h \
        ./src/unix-socket-helper.h \

SOURCES += \
        ./src/main.cpp \
        ./src/daemon-instance.cpp \
        ./src/network-log.cpp \
        ./src/unix-socket-helper.cpp \
