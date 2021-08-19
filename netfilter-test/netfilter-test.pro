TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        Ip.cpp \
        main.cpp

HEADERS += \
    Ip.h \
    IpHdr.h \
    TcpHdr.h

LIBS += -lnetfilter_queue
