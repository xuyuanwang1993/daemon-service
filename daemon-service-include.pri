#定义其依赖的库及包含目录
INCLUDEPATH += $$PWD/src \


LIBS += -L$$DESTDIR

linux-* {
    LIBS += -lpthread -pthread
    QMAKE_LFLAGS += -rdynamic
} else: win32 {

}
#禁止引用自身
linux-* {
    LIBS -= -l$${TARGET}
} else: win32 {
    LIBS -= -llib$${TARGET}
}
