#include "desktop_rpc.h"
#include "desktop_values.h"
#include <QCoreApplication>
#include <QEventLoop>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTemporaryDir>
#include <QTimer>
#include <iostream>
#include <memory>
#include <stdexcept>

static void check(bool condition, const char* message) {
    if (!condition) throw std::runtime_error(message);
}
int main(int argc, char** argv) {
    QCoreApplication app(argc, argv);
    try {
        check(DesktopRpc::validEndpoint(QUrl("http://127.0.0.1:21832/rpc")), "loopback should be allowed");
        for (const auto& bad : {"http://example.com:21832/rpc", "http://127.0.0.1:21832/other", "http://user:pass@127.0.0.1:21832/rpc", "http://127.0.0.1:21832/rpc?token=secret", "http://127.0.0.1:21832/rpc#fragment"})
            check(!DesktopRpc::validEndpoint(QUrl(bad)), "noncanonical endpoint accepted");
        std::uint64_t value = 0;
        check(tru_desktop::positiveUnits("18446744073709551615", value) && value == UINT64_MAX, "uint64 maximum parse failed");
        for (const auto& bad : {"", "-1", "1.5", "1e6", "+1", "0", "18446744073709551616"})
            check(!tru_desktop::positiveUnits(bad, value), "invalid amount accepted");
        check(tru_desktop::littleEndianHex(0x12345678, 4) == "78563412", "timelock endian mismatch");
        check(tru_desktop::littleEndianHex(UINT64_MAX, 8) == "ffffffffffffffff", "oracle endian mismatch");
        const QByteArray exact = "{\"amountAtoms\":18446744073709551615}";
        check(DesktopRpc::requestBody(1, "method", exact).contains(exact), "uint64 JSON rounded");

        QTcpServer server;
        check(server.listen(QHostAddress::LocalHost, 0), "cannot open loopback test server");
        DesktopRpc rpc;
        QString error;
        QTemporaryDir tmp;
        const QString cookiePath = tmp.filePath("cookie");
        { QFile f(cookiePath); check(f.open(QIODevice::WriteOnly), "cookie creation failed"); f.write(QByteArray(64, 'a')); }
        check(rpc.configure(QUrl(QString("http://127.0.0.1:%1/rpc").arg(server.serverPort())), cookiePath, error), "configuration failed");
        int received = 0;
        int mode = 0;
        bool exactSeen = false;
        QObject::connect(&server, &QTcpServer::newConnection, &app, [&] {
            while (server.hasPendingConnections()) {
                auto socket = server.nextPendingConnection();
                auto data = std::make_shared<QByteArray>();
                auto handled = std::make_shared<bool>(false);
                QObject::connect(socket, &QTcpSocket::readyRead, socket, [&, socket, data, handled] {
                    *data += socket->readAll();
                    if (*handled) return;
                    const int split = data->indexOf("\r\n\r\n");
                    if (split < 0) return;
                    const QByteArray headers = data->left(split);
                    int expected = 0;
                    for (auto line : headers.split('\n')) if (line.toLower().startsWith("content-length:")) expected = line.mid(15).trimmed().toInt();
                    if (data->size() - split - 4 < expected) return;
                    *handled = true;
                    ++received;
                    const auto body = data->mid(split + 4, expected);
                    exactSeen = body.contains(exact);
                    check(headers.contains("Authorization: Bearer " + QByteArray(64, 'a')), "cookie not used as bearer token");
                    const int id = QJsonDocument::fromJson(body).object().value("id").toInt();
                    QByteArray response;
                    QByteArray status = "200 OK";
                    QByteArray extra;
                    if (mode == 1) response = "{\"error\":{\"code\":-32000,\"message\":\"Rejected non-standard output script\"}}";
                    else if (mode == 2) response = "{\"id\":999,\"result\":{}}";
                    else if (mode == 3) { status = "302 Found"; extra = "Location: http://127.0.0.1:" + QByteArray::number(server.serverPort()) + "/redirected\r\n"; response = "{}"; }
                    else response = "{\"id\":" + QByteArray::number(id) + ",\"result\":{\"accepted\":true,\"amountAtoms\":18446744073709551615},\"error\":null}";
                    socket->write("HTTP/1.1 " + status + "\r\nContent-Type: application/json\r\nConnection: close\r\n" + extra + "Content-Length: " + QByteArray::number(response.size()) + "\r\n\r\n" + response);
                    socket->disconnectFromHost();
                });
                QObject::connect(socket, &QTcpSocket::disconnected, socket, &QObject::deleteLater);
            }
        });
        auto run = [&](int selected) {
            mode = selected;
            QEventLoop loop;
            QTimer deadline;
            deadline.setSingleShot(true);
            QObject::connect(&deadline, &QTimer::timeout, &loop, &QEventLoop::quit);
            bool completed = false;
            QString resultError;
            QByteArray resultRaw;
            rpc.call("test", exact, [&](const QJsonValue&, const QByteArray& raw, const QString& e) {
                completed = true; resultError = e; resultRaw = raw; loop.quit();
            });
            deadline.start(4000);
            if (!completed) loop.exec();
            check(completed, "request never completed");
            check(exactSeen, "request payload was rounded in transport");
            if (selected == 0) { check(resultError.isEmpty(), "valid success rejected"); check(resultRaw.contains("18446744073709551615"), "response precision lost"); }
            if (selected == 1) check(resultError == "Rejected non-standard output script", "RPC rejection lost");
            if (selected == 2) check(resultError.contains("Mismatched"), "wrong response id accepted");
            if (selected == 3) check(resultError.contains("302"), "redirect not rejected");
        };
        for (int modeNumber = 0; modeNumber < 4; ++modeNumber) run(modeNumber);
        check(received == 4, "transport retried a request or followed a redirect");
        bool rejected = false;
        rpc.call("test", "[]", [&](const QJsonValue&, const QByteArray&, const QString& e) { rejected = !e.isEmpty(); });
        check(rejected, "array parameters accepted");
        std::cout << "PASS: exact uint64 values; amount/endian guards; cookie auth; RPC errors; response ids; remote endpoint rejection; no redirect/retry; JSON object validation\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "FAIL: " << e.what() << '\n'; return 1;
    }
}
