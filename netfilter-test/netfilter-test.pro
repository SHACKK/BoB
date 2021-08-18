TEMPLATE = app
CONFIG += console
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += \
        Ip.cpp \
        main.c \
        nfqnl_test.c

HEADERS += \
    Ip.h \
    IpHdr.h \
    TcpHdr.h
