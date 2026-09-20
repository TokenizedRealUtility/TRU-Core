#pragma once

#include <QObject>
#include <QNetworkAccessManager>
#include <QJsonValue>
#include <QUrl>
#include <functional>

// GUI-DESKTOP-01: transport only; owns no wallet, chain or signing keys.
class DesktopRpc : public QObject {
public:
    using Callback = std::function<void(const QJsonValue&, const QByteArray&, const QString&)>;
    explicit DesktopRpc(QObject* parent = nullptr);
    bool configure(const QUrl& endpoint, const QString& cookieFile, QString& error);
    void setSessionToken(const QByteArray& token);
    void call(const QString& method, const QByteArray& objectParams, Callback callback);
    QUrl endpoint() const { return endpoint_; }
    static QString defaultCookiePath(int port);
    static bool validEndpoint(const QUrl& endpoint);
    static QByteArray requestBody(int id, const QString& method, const QByteArray& params);
private:
    QNetworkAccessManager network_;
    QUrl endpoint_;
    QString cookieFile_;
    QByteArray token_;
    int nextId_ = 1;
    int pending_ = 0;
};
