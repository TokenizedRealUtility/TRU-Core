#pragma once
// AXON Desktop Portal 01. Native Qt networking, in-memory portal sessions only.
// Does not read wallet secrets, store NEROMESH credentials, or sign HTLCs.
#include <QWidget>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QFormLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QComboBox>
#include <QPushButton>
#include <QPlainTextEdit>
#include <QMessageBox>
#include <QNetworkAccessManager>
#include <QNetworkCookieJar>
#include <QNetworkCookie>
#include <QNetworkRequest>
#include <QNetworkReply>
#include <QJsonDocument>
#include <QJsonArray>
#include <QJsonObject>
#include <QUrl>
#include <QRegularExpression>
#include <QDateTime>
#include <functional>

class TruAxonPortalWidget final : public QWidget {
public:
    explicit TruAxonPortalWidget(std::function<void(const QString&)> fundingHandoff,
                                 QWidget* parent=nullptr)
        : QWidget(parent), fundingHandoff_(std::move(fundingHandoff)) {
        net_.setCookieJar(new QNetworkCookieJar(&net_)); // RAM only; never QSettings
        auto* outer = new QVBoxLayout(this);
        auto* headline = new QLabel("AXON  /  NEROMESH   0.5.0");
        headline->setStyleSheet("font-size:24px;font-weight:bold;color:#67e9eb");
        outer->addWidget(headline);
        auto* note = new QLabel("TRU-native compute marketplace. Customer and worker portals, live jobs and non-custodial 20%/80% settlement. NEROMESH operates independently of Core.");
        note->setWordWrap(true); outer->addWidget(note);
        auto* warning = new QLabel("Private prompts may be processed by independent worker machines. Never enter seeds, wallet passphrases, passwords or API credentials as job content. Real TRU is used for funded work.");
        warning->setWordWrap(true); warning->setStyleSheet("color:#ffca78"); outer->addWidget(warning);
        auto* loginBox = new QGroupBox("PORTAL SESSION  /  MEMORY ONLY");
        auto* login = new QHBoxLayout(loginBox);
        role_ = new QComboBox; role_->addItems({"Customer", "Worker"});
        token_ = new QLineEdit; token_->setEchoMode(QLineEdit::Password);
        token_->setPlaceholderText("nmc_ customer or nmp_ worker portal credential");
        auto* signIn = new QPushButton("Connect");
        auto* signOut = new QPushButton("Disconnect");
        login->addWidget(role_);login->addWidget(token_,1);login->addWidget(signIn);login->addWidget(signOut);
        outer->addWidget(loginBox);
        auto* top = new QHBoxLayout;
        auto* network = new QPushButton("Network");
        auto* jobs = new QPushButton("My Jobs / Offers");
        auto* notices = new QPushButton("Notifications");
        auto* refresh = new QPushButton("Check AXON Health");
        top->addWidget(network);top->addWidget(jobs);top->addWidget(notices);top->addWidget(refresh);outer->addLayout(top);
        status_ = new QLabel("Offline / not connected");status_->setWordWrap(true);outer->addWidget(status_);
        output_ = new QPlainTextEdit;output_->setReadOnly(true);output_->setPlaceholderText("AXON network data and job details appear here.");
        outer->addWidget(output_,1);
        auto* actionBox = new QGroupBox("JOB ACTIONS  /  EXPLICIT APPROVAL");
        auto* actionLayout=new QVBoxLayout(actionBox);
        auto* input = new QHBoxLayout;
        job_ = new QLineEdit; job_->setPlaceholderText("AXN-XXXXXXXXXXXX");
        auto* fund = new QPushButton("Create & Review Wallet Handoff");
        input->addWidget(job_,1);input->addWidget(fund);actionLayout->addLayout(input);
        auto* second=new QHBoxLayout;
        auto* workerAccept=new QPushButton("Accept Worker Offer");
        auto* workerDecline=new QPushButton("Decline Offer");
        auto* customerAccept=new QPushButton("Accept Customer Result / Release 80%");
        auto* settlement=new QPushButton("Worker Settlement Details");
        second->addWidget(workerAccept);second->addWidget(workerDecline);
        second->addWidget(customerAccept);second->addWidget(settlement);
        actionLayout->addLayout(second);outer->addWidget(actionBox);
        connect(signIn,&QPushButton::clicked,this,[this]{ login(); });
        connect(signOut,&QPushButton::clicked,this,[this]{ logout(); });
        connect(network,&QPushButton::clicked,this,[this]{ fetch("/api/v1/network/summary",[this](const QJsonObject& o){ showJson(o); }); });
        connect(refresh,&QPushButton::clicked,this,[this]{ fetch("/api/health",[this](const QJsonObject& o){
            status_->setText("AXON server: " + o.value("release").toString() + " / " + o.value("status").toString()); showJson(o);
        }); });
        connect(jobs,&QPushButton::clicked,this,[this]{
            if (!connected_) return requireSession();
            fetch(role_->currentIndex()==0?"/api/v1/portal/customer/jobs":"/api/v1/portal/worker/offers",
                  [this](const QJsonObject& o){ showJobs(o); });
        });
        connect(notices,&QPushButton::clicked,this,[this]{
            if (!connected_) return requireSession();
            fetch("/api/v1/portal/notifications",[this](const QJsonObject& o){showJson(o);});
        });
        connect(fund,&QPushButton::clicked,this,[this]{
            if (!customer()) return;
            const QString id=checkedJob();if(id.isEmpty())return;
            if(QMessageBox::question(this,"Create wallet handoff",
                    "Request a short-lived funding intent for " + id + "? Core will separately preview the amounts and request approval before moving TRU.",
                    QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
            post("/api/v1/portal/customer/jobs/"+id+"/handoff",{},[this,id](const QJsonObject& o){
                const QString uri=o.value("wallet_uri").toString();
                if (!uri.startsWith("tru://axon/fund/AXI-")) {
                    QMessageBox::warning(this,"AXON","Server did not return a valid wallet handoff URI.");return;
                }
                status_->setText("Handoff created for " + id + ". Review amounts in local Core.");
                fundingHandoff_(uri); // capability never displayed, persisted, or logged
            });
        });
        connect(workerAccept,&QPushButton::clicked,this,[this]{ actWorker("accept"); });
        connect(workerDecline,&QPushButton::clicked,this,[this]{ actWorker("decline"); });
        connect(customerAccept,&QPushButton::clicked,this,[this]{
            if(!customer())return;const QString id=checkedJob();if(id.isEmpty())return;
            if(QMessageBox::warning(this,"Release acceptance reward",
                "Only accept after reviewing the actual completed job and verifying the result. This releases the 80% acceptance preimage for " + id + ". Continue?",
                QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
            post("/api/v1/portal/customer/jobs/"+id+"/accept",{},[this](const QJsonObject&){status_->setText("Acceptance submitted. Verify settlement state.");});
        });
        connect(settlement,&QPushButton::clicked,this,[this]{
            if(!worker())return;const QString id=checkedJob();if(id.isEmpty())return;
            fetch("/api/v1/portal/worker/jobs/"+id+"/settlement",[this](const QJsonObject& o){
                // Secrets and preimages are sensitive. Only reveal after explicit consent.
                if(QMessageBox::question(this,"Show settlement secrets",
                    "Settlement output may contain HTLC preimages. Display them on this screen? Never share them publicly.",
                    QMessageBox::Yes|QMessageBox::No,QMessageBox::No)==QMessageBox::Yes)showJson(o);
                else status_->setText("Settlement retrieved; sensitive data not displayed.");
            });
        });
        connect(role_,QOverload<int>::of(&QComboBox::currentIndexChanged),this,[this](int){
            connected_=false;net_.setCookieJar(new QNetworkCookieJar(&net_));token_->clear();
            output_->clear();status_->setText("Role changed. Sign in again.");
        });
        fetch("/api/health",[this](const QJsonObject& o){
            status_->setText("AXON " + o.value("release").toString() + " / " + o.value("status").toString());
        });
    }
private:
    const QUrl base_{"https://tru.neromesh.space"}; // fixed gateway; never user input
    QNetworkAccessManager net_;
    std::function<void(const QString&)> fundingHandoff_;
    QComboBox* role_{};QLineEdit* token_{};QLineEdit* job_{};
    QLabel* status_{};QPlainTextEdit* output_{};
    bool connected_=false;
    void requireSession(){QMessageBox::information(this,"AXON","Connect a customer or worker account first.");}
    bool customer(){if(!connected_||role_->currentIndex()!=0){requireSession();return false;}return true;}
    bool worker(){if(!connected_||role_->currentIndex()!=1){requireSession();return false;}return true;}
    QString checkedJob(){QString id=job_->text().trimmed().toUpper();
        if(!QRegularExpression("^AXN-[0-9A-F]{12}$").match(id).hasMatch()){
            QMessageBox::warning(this,"AXON","Enter a valid AXN- job ID.");return {};
        }return id;
    }
    void showJson(const QJsonObject& o){output_->setPlainText(QString::fromUtf8(QJsonDocument(o).toJson(QJsonDocument::Indented)));}
    void showJobs(const QJsonObject& o){
        // Redact reward preimages, opaque capabilities and other access credentials.
        QJsonObject safe=o;
        auto arr=o.value("offers").toArray();QJsonArray clean;
        for(const auto& entry:arr){QJsonObject x=entry.toObject();
            for(const QString& k:{"compute_preimage","acceptance_preimage","wallet_uri","capability","customer_token","worker_key"})x.remove(k);
            clean.append(x);
        }
        if(o.contains("offers"))safe.insert("offers",clean);
        showJson(safe);
    }
    void request(const QString& path,const QJsonObject* body,std::function<void(const QJsonObject&)> done){
        const QUrl url=base_.resolved(QUrl(path));
        if(url.scheme()!="https"||url.host()!=base_.host())return;
        QNetworkRequest q(url);q.setRawHeader("Accept","application/json");
        q.setRawHeader("Cache-Control","no-store");
#if QT_VERSION >= QT_VERSION_CHECK(5, 9, 0)
        q.setAttribute(QNetworkRequest::RedirectPolicyAttribute,QNetworkRequest::ManualRedirectPolicy);
#endif
        QNetworkReply* reply=nullptr;
        if(body){
            q.setHeader(QNetworkRequest::ContentTypeHeader,"application/json");
            const auto cookies=net_.cookieJar()->cookiesForUrl(base_);
            for(const auto& cookie:cookies){if(cookie.name()=="AXON_CSRF"){
                q.setRawHeader("X-CSRF-Token",cookie.value());break;
            }}
            reply=net_.post(q,QJsonDocument(*body).toJson(QJsonDocument::Compact));
        } else reply=net_.get(q);
        connect(reply,&QNetworkReply::finished,this,[this,reply,done]{
            const auto code=reply->attribute(QNetworkRequest::HttpStatusCodeAttribute).toInt();
            const QByteArray bytes=reply->readAll();
            const QJsonDocument doc=QJsonDocument::fromJson(bytes);
            const QJsonObject result=doc.isObject()?doc.object():QJsonObject{};
            const bool ok=reply->error()==QNetworkReply::NoError && code>=200 && code<300;
            if(!ok){
                // Do not dump response bodies, session cookies, credentials or funding capabilities.
                status_->setText(QString("AXON request failed (HTTP %1): %2").arg(code).arg(
                    result.value("error").toString("Check credentials, TLS and server availability.")));
            }else done(result);
            reply->deleteLater();
        });
    }
    void fetch(const QString& p,std::function<void(const QJsonObject&)> cb){request(p,nullptr,cb);}
    void post(const QString& p,const QJsonObject& b,std::function<void(const QJsonObject&)> cb){request(p,&b,cb);}
    void login(){
        const QString credential=token_->text().trimmed();
        const bool customerRole=role_->currentIndex()==0;
        if(!credential.startsWith(customerRole?"nmc_":"nmp_")){
            QMessageBox::warning(this,"AXON","Enter the correct portal credential type for this role.");return;
        }
        QJsonObject payload;payload.insert(customerRole?"customer_token":"worker_key",credential);
        // Clear the UI immediately; no password/credential stored to disk.
        token_->clear();
        post(customerRole?"/api/v1/portal/customer/login":"/api/v1/portal/worker/login",payload,
             [this](const QJsonObject& o){
                 connected_=o.value("authenticated").toBool();
                 status_->setText(connected_?"AXON portal connected (in-memory session)":"AXON login rejected");
             });
        payload={};
    }
    void logout(){
        if(connected_)post("/api/v1/portal/logout",{},[this](const QJsonObject&){
            status_->setText("AXON disconnected");
        });
        connected_=false;token_->clear();output_->clear();
        net_.setCookieJar(new QNetworkCookieJar(&net_));
    }
    void actWorker(const QString& action){
        if(!worker())return;const QString id=checkedJob();if(id.isEmpty())return;
        const QString warning=action=="accept"?
            "Reserve this offer for your worker? Your worker's claim public key must already be configured. No funds move until the customer pays.":
            "Decline this open offer?";
        if(QMessageBox::question(this,"AXON worker",warning,QMessageBox::Yes|QMessageBox::No,QMessageBox::No)!=QMessageBox::Yes)return;
        post("/api/v1/portal/worker/jobs/"+id+"/"+action,{},[this](const QJsonObject& o){
            status_->setText("Worker action received. Refresh to confirm current state.");showJobs(o);
        });
    }
};
