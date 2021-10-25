#与平台有关的配置
win32:{
PLATFORM_DIR=win32
}

linux-g++:{
PLATFORM_DIR=linux
}

linux-arm-gnueabi-g++:{
PLATFORM_DIR=linux-arm
}
linux-aarch64-gnu-g++:{

PLATFORM_DIR=linux-aarch64
}
CONFIG(debug,debug|release){

PLATFORM_DIR=$${PLATFORM_DIR}d

DEFINES +=  DEBUG

}
#生成目录
DESTDIR = $$PWD/../build/$$PLATFORM_DIR
