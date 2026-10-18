#pragma once
// MARKET-03A: Qt-only desktop rendezvous. No server, RPC signing or private keys.
#include "tru_market_login_v1.h"
#include <QNetworkAccessManager>
#include <QPointer>
#include <QUrl>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QEventLoop>
#include <QTimer>
#include <QDateTime>
#include <QJsonDocument>
#include <QJsonObject>
#include <QInputDialog>
#include <QLineEdit>
#include <QStringList>
#include <QMessageBox>
#include <QFile>
#include <QFileInfo>
#include <QDir>
#include <QRegularExpression>
#include <functional>
#include <stdexcept>

namespace tru_market_connect_qt_v2 {
inline QJsonObject post(const QString& route, const QJsonObject& body) {
    QNetworkAccessManager manager;
    manager.setProxy(QNetworkProxy(QNetworkProxy::NoProxy));
    QNetworkRequest request(QUrl("https://market.tokenizedrealutility.com/api/connect/"+route));
    request.setHeader(QNetworkRequest::ContentTypeHeader,"application/json");
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::ManualRedirectPolicy);
    auto* reply=manager.post(request,QJsonDocument(body).toJson(QJsonDocument::Compact));
    QEventLoop loop; QTimer timer; timer.setSingleShot(true);
    QObject::connect(&timer,&QTimer::timeout,reply,&QNetworkReply::abort);
    QObject::connect(reply,&QNetworkReply::finished,&loop,&QEventLoop::quit);
    QByteArray bytes; bool oversized=false;
    QObject::connect(reply,&QNetworkReply::readyRead,[&]{
        bytes+=reply->readAll();
        if(bytes.size()>65536){oversized=true;reply->abort();}
    });
    timer.start(15000); loop.exec(); timer.stop(); bytes+=reply->readAll();
    if(oversized || bytes.size()>65536)throw std::runtime_error("Marketplace response too large");
    if(reply->error()!=QNetworkReply::NoError || reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt()!=200)
        throw std::runtime_error("Marketplace request failed or expired. Start a new connection in your browser.");
    QJsonParseError error; const auto doc=QJsonDocument::fromJson(bytes,&error);
    if(error.error!=QJsonParseError::NoError || !doc.isObject())throw std::runtime_error("Invalid marketplace response");
    return doc.object();
}
inline QString inbox(){return QDir::homePath()+"/.local/share/tru-market-connect/desktop-connect.json";}
inline QString takeUri(){
    const QString path=inbox(); QFileInfo info(path);
    if(!info.exists())return {};
    // The inbox can only initiate an explicitly confirmed login. It never carries keys or signatures.
    if(info.isSymLink() || !info.isFile() || info.size()>2048)return {};
    QFile f(path); if(!f.open(QIODevice::ReadOnly))return {};
    const auto bytes=f.read(2049); f.close(); if(!f.remove() || bytes.size()>2048)return {};
    const auto obj=QJsonDocument::fromJson(bytes).object();
    const qint64 expires=static_cast<qint64>(obj.value("expires").toDouble());
    if(expires<=QDateTime::currentSecsSinceEpoch() || expires>QDateTime::currentSecsSinceEpoch()+310)return {};
    return obj.value("uri").toString();
}
using Sign=std::function<bool(const QString&,const QString&,QString&,QString&,QString&)>;
inline void run(QWidget* parent, const QString& uri,
                const std::function<QStringList()>& accounts,const Sign& sign){
    QPointer<QWidget> owner(parent);
    try {
        QJsonObject access;
        if(uri.isEmpty()){
            bool ok=false;
            QString pair=QInputDialog::getText(parent,"Connect Marketplace",
                "In the marketplace choose Connect > Desktop Wallet.\n"
                "Paste the 16-character pairing code (XXXX-XXXX-XXXX-XXXX).\n"
                "The 8-character verification code is compared later:",QLineEdit::Normal,{},&ok);
            if(!ok)return;
            pair=pair.toUpper();pair.remove(QRegularExpression("[\\s-]"));
            if(!QRegularExpression("^[0-9A-F]{16}$").match(pair).hasMatch())throw std::runtime_error("Enter the 16-character pairing code from Desktop Wallet in the marketplace. The 8-character verification code is only for comparison.");
            const auto ticket=post("redeem",{{"pairing_code",pair},{"wallet","desktop"}});
            if(!owner)return;
            access={{"id",ticket.value("id")},{"secret",ticket.value("secret")}};
        }else{
            const auto match=QRegularExpression("^tru-market://connect/desktop/([0-9a-f]{32})/([0-9a-f]{64})$").match(uri);
            if(!match.hasMatch())throw std::runtime_error("Invalid marketplace link");
            access={{"id",match.captured(1)},{"secret",match.captured(2)}};
        }
        const QString id=access.value("id").toString(), secret=access.value("secret").toString();
        if(!QRegularExpression("^[0-9a-f]{32}$").match(id).hasMatch() || !QRegularExpression("^[0-9a-f]{64}$").match(secret).hasMatch())
            throw std::runtime_error("Invalid marketplace ticket");
        const QString code=id.left(8).toUpper();
        QStringList addresses=accounts();
        for(int i=addresses.size()-1;i>=0;--i)
            if(!QRegularExpression("^T[1-9A-HJ-NP-Za-km-z]{33}$").match(addresses[i]).hasMatch())addresses.removeAt(i);
        if(addresses.isEmpty())throw std::runtime_error("Unlock a wallet containing an address first");
        bool ok=true;
        const QString address=addresses.size()==1?addresses.first():QInputDialog::getItem(parent,"Connect Marketplace","Select your address",addresses,0,false,&ok);
        if(!ok)return;
        auto claim=access; claim.insert("address",address);
        const auto c=post("claim",claim);
        if(!owner)return;
        tru_market_login_v1::Challenge parsed;std::string reason;
        const auto message=c.value("message").toString();
        if(!tru_market_login_v1::parse(message.toStdString(),parsed,reason) || QString::fromStdString(parsed.address)!=address ||
           c.value("address").toString()!=address || c.value("nonce").toString()!=QString::fromStdString(parsed.nonce) ||
           c.value("code").toString()!=code || c.value("network").toString()!="tru-mainnet")
            throw std::runtime_error("Marketplace challenge mismatch");
        if(QMessageBox::question(parent,"Approve Marketplace Login",
            "Site: https://market.tokenizedrealutility.com\nNetwork: tru-mainnet\n\nAddress: "+address+
            "\nMatch browser verification code: "+code+"\n\nConnect this address? Login only. No payment permission.",
            QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
        if(!tru_market_login_v1::parse(message.toStdString(),parsed,reason))throw std::runtime_error(reason);
        QString pub,sig,error;
        if(!sign(address,message,pub,sig,error))throw std::runtime_error(error.toStdString());
        auto proof=access;proof.insert("address",address);proof.insert("nonce",QString::fromStdString(parsed.nonce));
        proof.insert("pubkey_hex",pub);proof.insert("signature_hex",sig);post("proof",proof);
        if(!owner)return;
        QMessageBox::information(parent,"Marketplace Connected","Approved. Return to your marketplace browser.");
    }catch(const std::exception& e){if(!owner)return;QMessageBox::warning(parent,"Marketplace Connection",QString::fromUtf8(e.what()));}
}
} // namespace
