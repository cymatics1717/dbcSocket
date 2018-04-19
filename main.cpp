#include <QCoreApplication>
#include <QCommandLineParser>
#include <QNetworkDatagram>
#include <QDateTime>
#include <QUdpSocket>
#include <QTimer>
#include <QDataStream>
#include <iostream>
#include <bitset>
#include "dbchandler.h"
#define STAMP "yyyyMMdd HH:mm:ss.zzz"
#define DEFAULT_MESSAGE "BCU_04"

static unsigned char crc_table[256] = {
    0x0, 0x1D, 0x3A, 0x27, 0x74, 0x69, 0x4E, 0x53,
    0xE8, 0xF5, 0xD2, 0xCF, 0x9C, 0x81, 0xA6, 0xBB,
    0xCD, 0xD0, 0xF7, 0xEA, 0xB9, 0xA4, 0x83, 0x9E,
    0x25, 0x38, 0x1F, 0x2, 0x51, 0x4C, 0x6B, 0x76,
    0x87, 0x9A, 0xBD, 0xA0, 0xF3, 0xEE, 0xC9, 0xD4,
    0x6F, 0x72, 0x55, 0x48, 0x1B, 0x6, 0x21, 0x3C,
    0x4A, 0x57, 0x70, 0x6D, 0x3E, 0x23, 0x4, 0x19,
    0xA2, 0xBF, 0x98, 0x85, 0xD6, 0xCB, 0xEC, 0xF1,
    0x13, 0xE, 0x29, 0x34, 0x67, 0x7A, 0x5D, 0x40,
    0xFB, 0xE6, 0xC1, 0xDC, 0x8F, 0x92, 0xB5, 0xA8,
    0xDE, 0xC3, 0xE4, 0xF9, 0xAA, 0xB7, 0x90, 0x8D,
    0x36, 0x2B, 0xC, 0x11, 0x42, 0x5F, 0x78, 0x65,
    0x94, 0x89, 0xAE, 0xB3, 0xE0, 0xFD, 0xDA, 0xC7,
    0x7C, 0x61, 0x46, 0x5B, 0x8, 0x15, 0x32, 0x2F,
    0x59, 0x44, 0x63, 0x7E, 0x2D, 0x30, 0x17, 0xA,
    0xB1, 0xAC, 0x8B, 0x96, 0xC5, 0xD8, 0xFF, 0xE2,
    0x26, 0x3B, 0x1C, 0x1, 0x52, 0x4F, 0x68, 0x75,
    0xCE, 0xD3, 0xF4, 0xE9, 0xBA, 0xA7, 0x80, 0x9D,
    0xEB, 0xF6, 0xD1, 0xCC, 0x9F, 0x82, 0xA5, 0xB8,
    0x3, 0x1E, 0x39, 0x24, 0x77, 0x6A, 0x4D, 0x50,
    0xA1, 0xBC, 0x9B, 0x86, 0xD5, 0xC8, 0xEF, 0xF2,
    0x49, 0x54, 0x73, 0x6E, 0x3D, 0x20, 0x7, 0x1A,
    0x6C, 0x71, 0x56, 0x4B, 0x18, 0x5, 0x22, 0x3F,
    0x84, 0x99, 0xBE, 0xA3, 0xF0, 0xED, 0xCA, 0xD7,
    0x35, 0x28, 0xF, 0x12, 0x41, 0x5C, 0x7B, 0x66,
    0xDD, 0xC0, 0xE7, 0xFA, 0xA9, 0xB4, 0x93, 0x8E,
    0xF8, 0xE5, 0xC2, 0xDF, 0x8C, 0x91, 0xB6, 0xAB,
    0x10, 0xD, 0x2A, 0x37, 0x64, 0x79, 0x5E, 0x43,
    0xB2, 0xAF, 0x88, 0x95, 0xC6, 0xDB, 0xFC, 0xE1,
    0x5A, 0x47, 0x60, 0x7D, 0x2E, 0x33, 0x14, 0x9,
    0x7F, 0x62, 0x45, 0x58, 0xB, 0x16, 0x31, 0x2C,
    0x97, 0x8A, 0xAD, 0xB0, 0xE3, 0xFE, 0xD9, 0xC4,
};

static unsigned char get_crc_result(const unsigned char *buf, int len)
{
    const unsigned char *ptr = buf;
    unsigned char _crc = 0xFF;

    while (len--)
        _crc = crc_table[_crc ^ *ptr++];

    return ~_crc;
}

int main(int argc, char *argv[])
{
    QCoreApplication app(argc, argv);
    app.setApplicationVersion(QDateTime::currentDateTime().toString(STAMP));

    QCommandLineParser p;
    p.setApplicationDescription("DBC data with UDP network emulator");
    p.addHelpOption();
    p.addVersionOption();
    p.addOption({{"t", "inteval"}, "timer inteval. ms,default is 1000ms","t","1000"});
    p.addOption({{"m", "message-name"}, "message name. string,default is " DEFAULT_MESSAGE,"m",DEFAULT_MESSAGE});
    p.addOption({{"I", "message-id"}, "message ID. int,default is 91","I","91"});
    p.addOption({{"s", "signal"}, "signal name. string","s",""});
    p.addOption({{"f", "fixed"}, "fixed signal value. hex integer","f","0"});
    p.addOption({{"i", "ip"}, "UDP host IP. string,default is 127.0.0.1","i","127.0.0.1"});
    p.addOption({{"p", "port"}, "UDP host port,int. default is 20002","p","20002"});
    p.addOption({{"V","verbose"}, "Verbose mode. Prints out more information."});
    p.addOption({{"l","list-all"}, "Verbose mode. Prints out more information."});
    p.addPositionalArgument("input", "a DBC file path.", "input");
    p.process(app);

    QStringList arglist = p.positionalArguments();

    int fixedSignal;
    QUdpSocket sock;
    QNetworkDatagram gram;
    auto udpsending = [&](const DBC_MESSAGE *message,DBC_SIGNAL *sig, int cycletime){
        if(not message or message->len>8) return ;

        static quint64 cnt = 0,mask;
        cnt++;
        if(sig){
            mask = cnt%(0x1LL<<sig->signalSize);
            mask = mask << (sig->startBit-sig->signalSize+1);
        } else {
            mask = cnt;
        }

        QByteArray upacket;
        QDataStream stream(&upacket, QIODevice::ReadWrite);
        stream.setByteOrder(QDataStream::BigEndian);
        stream << quint32(message->ID);
        stream << quint8(message->len);

        QByteArray tmp;
        QDataStream sss(&tmp, QIODevice::ReadWrite);
        sss.setByteOrder(QDataStream::LittleEndian);
        sss << mask + fixedSignal;

        QByteArray payload;
        DBC_SIGNAL *crc = message->crcSignal;
        if(crc){
            payload = tmp.left(message->len-1);
            unsigned char result = get_crc_result((const unsigned char *)payload.constData(),payload.size());
            if(crc->startBit == 7){
                upacket.append(quint8(result));
                upacket.append(payload);
            } else if(crc->startBit == 63){
                upacket.append(payload);
                upacket.append(quint8(result));
            }
        } else {
            payload = tmp.left(message->len);
            upacket.append(payload);
        }

        gram.setData(upacket);
        gram.setDestination(QHostAddress(p.value("i")),quint16(p.value("p").toInt()));
        sock.writeDatagram(gram);

        QString ss = "";
        if(sig) ss = QString("%1 %2|%3").arg(sig->name,-1,QChar('.')).arg(sig->startBit,2).arg(sig->signalSize,-2);
        qInfo().noquote()<<p.value("i")<<p.value("p")<<cycletime<<"["<<message->name<<message->ID <<message->len<< ss<<"]"
                        << gram.data().toHex('-');
    };

    if(arglist.isEmpty()) {
        p.showHelp();
    } else {
        DBCFile newFile;
        newFile.loadFile(arglist.at(0));

        DBCMessageHandler *messageHandler = newFile.messageHandler;
        DBC_MESSAGE *message = nullptr;
        if(p.isSet("m")){
            message = messageHandler->findMsgByName(p.value("m"));
        } else if(p.isSet("I")){
            message = messageHandler->findMsgByID(quint32(p.value("I").toInt()));
        }

        if(p.isSet("f")){
            QStringList lst = p.value("f").split(":");
            fixedSignal = 0;
            for(auto sig:lst){
                QStringList kv = sig.split("#");
                if(kv.size()==3){
                    DBC_MESSAGE *msg = messageHandler->findMsgByName(kv.at(0));
                    if(msg){
                        DBCSignalHandler *sigHandler = msg->sigHandler;
                        if(sigHandler){
                            DBC_SIGNAL *s = sigHandler->findSignalByName(kv.at(1));
                            if(s){
                                qInfo().noquote() << kv.at(0) << kv.at(1)<< kv.at(2) << s->startBit << s->signalSize;
                                int value = 0;
                                if(kv.at(2).startsWith("0x")){
                                    QString v = kv.at(2).right(kv.at(2).size()-2);
                                    value = v.toInt(nullptr,16);
                                } else {
                                    value = kv.at(2).toInt(nullptr,10);
                                }
                                fixedSignal += (value << (s->startBit-s->signalSize+1));
                            }
                        }
                    }
                }
            }
            qInfo().noquote() << QString(40,'-');
        }

        int cycletime = 1000;
        if(message){
            DBC_ATTRIBUTE_VALUE *attr = message->findAttrValByName("GenMsgCycleTime");
            if(attr) cycletime = attr->value.toInt();
            if(p.isSet("t")) cycletime = p.value("t").toInt();
            if(arglist.size()>1) cycletime = arglist.at(1).toInt();

            DBCSignalHandler *sigHandler = message->sigHandler;
            if(p.isSet("V")||p.isSet("l")){
                qInfo().noquote()<<QString("MsgID: %1name: %2%3 bytes %4 ms %5").arg(message->ID,-6)
                                   .arg(message->name,-30,QChar('.')).arg(message->len,2).arg(cycletime,4).arg(message->sender->name);
                for(int i=0;i<sigHandler->getCount();++i){
                    DBC_SIGNAL *s = sigHandler->findSignalByIdx(i);
                    qInfo().noquote()<<QString("%1 %2|%3 %4 %5").arg(s->name,-20,QChar('.')).arg(s->startBit,2)
                                       .arg(s->signalSize,-2).arg(s->receiver->name).arg(s->comment);
                }
                return 0;
            }
            DBC_SIGNAL *sig = sigHandler->findSignalByName(p.value("s"));
            auto timer = new QTimer(&app);
            QObject::connect(timer,&QTimer::timeout,std::bind(udpsending,message,sig,cycletime));
            timer->start(cycletime);
        } else {
            for(int m=0;m<messageHandler->getCount();++m){
                DBC_MESSAGE *msg = messageHandler->findMsgByIdx(m);
                DBC_ATTRIBUTE_VALUE *attr = msg->findAttrValByName("GenMsgCycleTime");
                int tmp= attr?attr->value.toInt():0;
                if(p.isSet("V")||p.isSet("l")){
                    DBC_SIGNAL *crc = msg->crcSignal;
                    QString crcs = "";
                    if(crc) crcs = QString("%1%2|%3").arg(crc->name,-20,QChar('.')).arg(crc->startBit,2).arg(crc->signalSize,-2);
                    qInfo().noquote()<<QString("%1MsgID: %2name: %3%4 bytes %5 ms %6 %7").arg(m,-4).arg(msg->ID,-6)
                                       .arg(msg->name,-30,QChar('.')).arg(msg->len,2).arg(tmp,4).arg(msg->sender->name).arg(crcs);
                } else {
                    if(tmp>0){
                        auto timer = new QTimer(&app);
                        QObject::connect(timer,&QTimer::timeout,std::bind(udpsending,msg,nullptr,tmp));
                        timer->start(tmp);
                    }
                }
            }
            if(p.isSet("V")||p.isSet("l")) return 0;
        }
    }
    return app.exec();
}
