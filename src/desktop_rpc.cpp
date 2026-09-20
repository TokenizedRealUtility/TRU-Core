#include "desktop_rpc.h"
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QNetworkProxy>
#include <QNetworkReply>
#include <QNetworkRequest>
#include <QTimer>
#include <climits>
#include <memory>

DesktopRpc::DesktopRpc(QObject* parent) : QObject(parent), network_(this) {
    network_.setProxy(QNetworkProxy::NoProxy);
}

QString DesktopRpc::defaultCookiePath(int port) {
    const QString overridePath = qEnvironmentVariable("TRU_RPC_COOKIE_FILE");
    if (!overridePath.isEmpty()) return overridePath;
#ifdef Q_OS_WIN
    return QDir(qEnvironmentVariable("LOCALAPPDATA", QDir::homePath()))
        .filePath(QString("TRU/rpc-cookie-%1").arg(port));
#else
    return QDir::home().filePath(QString(".tru/rpc-cookie-%1").arg(port));
#endif
}

bool DesktopRpc::isRemoteEndpoint(const QUrl& url) {
    const QString host = url.host().toLower();

    return url.isValid() &&
        host != "127.0.0.1" &&
        host != "::1" &&
        host != "localhost";
}

bool DesktopRpc::validEndpoint(const QUrl& url) {
    if (!url.isValid() ||
        url.host().isEmpty() ||
        url.path() != "/rpc" ||
        !url.userInfo().isEmpty() ||
        url.hasQuery() ||
        url.hasFragment()) {
        return false;
    }

    const int explicitPort = url.port(-1);

    if (explicitPort != -1 &&
        (explicitPort < 1 || explicitPort > 65535)) {
        return false;
    }

    const QString host = url.host().toLower();

    const bool loopback =
        host == "127.0.0.1" ||
        host == "::1" ||
        host == "localhost";

    // Local Core preserves the existing HTTP + loopback boundary.
    if (loopback)
        return url.scheme() == "http" &&
               explicitPort >= 1;

    // Remote Desktop RPC is TLS-only.
    // Standard HTTPS may use implicit port 443.
    return url.scheme() == "https";
}

bool DesktopRpc::configure(const QUrl& endpoint,
                           const QString& cookieFile,
                           QString& error) {
    if (pending_) {
        error = "Wait for the current requests to finish.";
        return false;
    }

    if (!validEndpoint(endpoint)) {
        error =
            "Local nodes must use "
            "http://127.0.0.1:<port>/rpc. "
            "Remote nodes must use "
            "https://<host>/rpc.";
        return false;
    }

    endpoint_ = endpoint;

    // Filesystem RPC cookies are local-Core credentials only.
    cookieFile_ = isRemoteEndpoint(endpoint)
        ? QString()
        : cookieFile;

    error.clear();
    return true;
}

void DesktopRpc::setSessionToken(const QByteArray& token) {
    token_.fill('\0');
    token_ = token;
}

QByteArray DesktopRpc::requestBody(int id, const QString& method, const QByteArray& params) {
    // Validate with Qt, but forward the original JSON bytes. Qt5's double-based
    // numeric model must never round a uint64 token amount or TRU atom value.
    QByteArray quoted = QJsonDocument(QJsonArray{method}).toJson(QJsonDocument::Compact);
    quoted = quoted.mid(1, quoted.size() - 2);
    return "{\"jsonrpc\":\"2.0\",\"id\":" + QByteArray::number(id) +
        ",\"method\":" + quoted + ",\"params\":" + params + "}";
}

void DesktopRpc::call(const QString& method, const QByteArray& params, Callback callback) {
    auto fail = [&](const QString& e) { callback({}, {}, e); };
    if (!validEndpoint(endpoint_)) { fail("Configure the node connection first."); return; }
    if (pending_ >= 8) { fail("Too many requests in progress. Try again shortly."); return; }
    QJsonParseError parseError;
    const auto parsed = QJsonDocument::fromJson(params, &parseError);
    if (params.size() > 8 * 1024 * 1024 || parseError.error != QJsonParseError::NoError || !parsed.isObject()) {
        fail("Parameters must be a JSON object of at most 8 MiB."); return;
    }
    QByteArray token = token_;

    // Environment and cookie fallback remain local-only.
    // Remote RPC requires an explicit in-memory session token.
    if (!isRemoteEndpoint(endpoint_)) {
        if (token.isEmpty())
            token = qgetenv("TRU_RPC_TOKEN").trimmed();

        if (token.isEmpty()) {
            QFileInfo info(cookieFile_);
            QFile cookie(cookieFile_);

            if (!info.isFile() ||
                info.isSymLink() ||
                info.size() > 514 ||
                !cookie.open(QIODevice::ReadOnly)) {

                fail(
                    "Cannot read the RPC cookie. "
                    "Start the node as this user, "
                    "or select its cookie in Connection."
                );

                return;
            }

            token = cookie.readAll().trimmed();
        }
    } else if (token.isEmpty()) {
        fail("Remote RPC requires a session access token.");
        return;
    }

    if (token.size() < 32 || token.size() > 512 || token.contains('\r') || token.contains('\n')) {
        fail("RPC token must be 32–512 characters without line breaks."); return;
    }
    if (nextId_ == INT_MAX) nextId_ = 1;
    const int id = nextId_++;
    QNetworkRequest request(endpoint_);
    request.setHeader(QNetworkRequest::ContentTypeHeader, "application/json");
    request.setRawHeader("Authorization", "Bearer " + token);
    request.setAttribute(QNetworkRequest::RedirectPolicyAttribute, QNetworkRequest::ManualRedirectPolicy);
    auto reply = network_.post(request, requestBody(id, method, params));
    token.fill('\0');
    ++pending_;
    auto body = std::make_shared<QByteArray>();
    auto timer = new QTimer(reply);
    timer->setSingleShot(true);
    connect(timer, &QTimer::timeout, reply, [reply] {
        reply->setProperty("truTimeout", true); reply->abort();
    });
    connect(reply, &QIODevice::readyRead, reply, [reply, body] {
        body->append(reply->readAll());
        if (body->size() > 20 * 1024 * 1024) {
            reply->setProperty("truOversize", true); reply->abort();
        }
    });
    connect(reply, &QNetworkReply::finished, this, [this, reply, timer, body, callback, id] {
        timer->stop();
        --pending_;
        body->append(reply->readAll());
        const int status = reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
        QString error;
        QJsonValue result;
        QJsonParseError pe;
        const auto doc = QJsonDocument::fromJson(*body, &pe);
        if (reply->property("truTimeout").toBool()) error = "Request timed out. A submitted operation may have completed; inspect the node before retrying.";
        else if (reply->property("truOversize").toBool()) error = "Response exceeded 20 MiB; narrow the query.";
        else if (status == 401 || status == 403) error = "RPC authentication refused. Verify the selected cookie or session token.";
        else if (status == 429) error = "Node is rate limiting requests. Wait before retrying.";
        else if (status != 200 || reply->error() != QNetworkReply::NoError)
            error = QString("RPC transport failed (HTTP %1): %2. Submission outcome may be unknown.").arg(status).arg(reply->errorString());
        else if (pe.error != QJsonParseError::NoError || !doc.isObject()) error = "Node returned an invalid JSON response.";
        else {
            const auto obj = doc.object();
            // Legacy error responses omit id; still report their real errors.
            if (obj.contains("error") && !obj.value("error").isNull()) {
                const auto e = obj.value("error");
                error = e.isObject() ? e.toObject().value("message").toString("RPC error") : e.toString("RPC error");
            } else if (obj.value("id").toInt(-1) != id || !obj.contains("result")) error = "Mismatched or incomplete RPC response.";
            else result = obj.value("result");
        }
        reply->deleteLater();
        // No automatic retries, particularly after an ambiguous write timeout.
        callback(result, *body, error);
    });
    timer->start(30000);
}
