#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <tlhelp32.h>
#include <QProcess>
#include <cstdlib> // for rand()

#include <QApplication>
#include <QMainWindow>
#include <QTabWidget>
#include <QListWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QLabel>
#include <QLineEdit>
#include <QCheckBox>
#include <QTableWidget>
#include <QHeaderView>
#include <QSystemTrayIcon>
#include <QMenu>
#include <QAction>
#include <QCloseEvent>
#include <QMessageBox>
#include <QTimer>
#include <QNetworkProxy>
#include <QSettings>
#include <QNetworkAccessManager>
#include <QNetworkReply>
#include <QEventLoop>
#include <QInputDialog>
#include <QSharedMemory>
#include <QListWidgetItem>
#include <QFont>
#include <QNetworkInterface>
#include <QTextEdit>
#include <QProgressBar>
#include <QThread>
#include <QFileDialog>
#include <QFileInfo>
#include <QFile>
#include <QDir>
#include <QTextStream>
#include <QStandardPaths>
#include <QComboBox>
#include <QSpinBox>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonArray>
#include <QTemporaryFile>
#include <QTime>
#include <QDateTime>
#include <QElapsedTimer>
#include <QMutex>
#include <QMutexLocker>
#include <QWaitCondition>
#include <QRegularExpression>
#include <QPointer>

// ساختار برای ذخیره اطلاعات پروکسی
struct ProxyItem
{
    QString name;
    QString type;
    QString address;
    int port;
    QString username;
    QString password;
    QString uuid;
    QString method;
    QString path;
    QString encryption;
    bool tls;
    bool isActive;
    int delay;
    QDateTime lastTestTime;
    QDateTime lastSuccessTime;
    int consecutiveTimeouts;

    ProxyItem() : consecutiveTimeouts(0) {}

    bool operator<(const ProxyItem &other) const
    {
        if (delay == -1 && other.delay == -1)
            return false;
        if (delay == -1)
            return false;
        if (other.delay == -1)
            return true;
        return delay < other.delay;
    }
};

// ساختار برای ذخیره اطلاعات اتصال
struct ConnectionInfo
{
    quint32 pid;
    QString processName;
    QString localAddress;
    QString remoteAddress;
    quint64 uploadBytes;
    quint64 downloadBytes;
    QDateTime startTime;
};

// ساختار برای ذخیره اطلاعات اپلیکیشن‌های مدیریت شده
struct ManagedApp
{
    QString name;
    QString path;
    quint64 totalUpload;
    quint64 totalDownload;
    bool useProxy;
    bool forceProxy;
    quint32 pid;
};

// ساختار برای تنظیمات sing-box
struct SingBoxConfig
{
    QString logLevel;
    bool logDisabled;
    QString logOutput;
    QString dnsServer;
    int socksPort;
    int httpPort;
    bool autoDetectInterface;
    QStringList dnsServers;
    bool enableSocks;
    bool enableHttp;
    bool allowLan; // جایگزین redirectAllTraffic
    QString outboundUsername; // برای احراز هویت کلاینت‌های متصل شونده به inbound
    QString outboundPassword;
    QString latencyTestUrl;
    int retryInterval; // به میلی‌ثانیه

    SingBoxConfig()
    {
        logLevel = "info";
        logDisabled = false;
        logOutput = "";
        dnsServer = "8.8.8.8";
        socksPort = 10808;
        httpPort = 10809;
        autoDetectInterface = true;
        enableSocks = true;
        enableHttp = true;
        dnsServers = QStringList() << "8.8.8.8" << "1.1.1.1";
        allowLan = false; // پیش‌فرض فقط localhost
        outboundUsername = "";
        outboundPassword = "";
        latencyTestUrl = "http://connectivitycheck.android.com/generate_204";
        retryInterval = 5000;
    }
};

// تابع کمکی برای کشتن پروسس‌های sing-box باقی‌مانده
void killExistingSingBox()
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(hSnapshot, &pe))
    {
        do
        {
            QString processName = QString::fromWCharArray(pe.szExeFile);
            if (processName.compare("sing-box.exe", Qt::CaseInsensitive) == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pe.th32ProcessID);
                if (hProcess)
                {
                    TerminateProcess(hProcess, 0);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }

    CloseHandle(hSnapshot);
}

// کلاس مدیریت ترافیک و ران‌تایم اپلیکیشن‌ها
class TrafficManager : public QObject
{
    Q_OBJECT
private:
    QMap<quint32, ConnectionInfo> connections;
    QTimer *updateTimer;
    QMap<QString, ManagedApp> managedApps;
    QTimer *appMonitorTimer;
    bool isUpdating;
    QMutex mutex;
    int updateCounter;
    static const int UPDATE_INTERVAL = 30000;
    static const int MONITOR_INTERVAL = 30000;

    // آمار کلی
    quint64 totalUpload;
    quint64 totalDownload;
    bool vpnActive; // وضعیت VPN

public:
    TrafficManager(QObject *parent = nullptr) : QObject(parent), isUpdating(false), updateCounter(0), totalUpload(0), totalDownload(0), vpnActive(false)
    {
        updateTimer = new QTimer(this);
        connect(updateTimer, &QTimer::timeout, this, &TrafficManager::updateConnections);
        updateTimer->start(UPDATE_INTERVAL);

        appMonitorTimer = new QTimer(this);
        connect(appMonitorTimer, &QTimer::timeout, this, &TrafficManager::monitorApplications);
        appMonitorTimer->start(MONITOR_INTERVAL);
    }

    void addManagedApp(const QString &name, const QString &path)
    {
        QMutexLocker locker(&mutex);
        if (!managedApps.contains(name))
        {
            ManagedApp app;
            app.name = name;
            app.path = path;
            app.totalUpload = 0;
            app.totalDownload = 0;
            app.useProxy = true;   // پیش‌فرض استفاده از پروکسی
            app.forceProxy = true; // پیش‌فرض اجبار به استفاده از پروکسی
            app.pid = 0;
            managedApps[name] = app;
        }
    }

    void removeManagedApp(const QString &name)
    {
        QMutexLocker locker(&mutex);
        managedApps.remove(name);
    }

    QMap<QString, ManagedApp> getManagedApps() const
    {
        return managedApps;
    }

    void setManagedAppUseProxy(const QString &name, bool useProxy)
    {
        QMutexLocker locker(&mutex);
        if (managedApps.contains(name))
        {
            managedApps[name].useProxy = useProxy;
        }
    }

    void setManagedAppForceProxy(const QString &name, bool forceProxy)
    {
        QMutexLocker locker(&mutex);
        if (managedApps.contains(name))
        {
            managedApps[name].forceProxy = forceProxy;
        }
    }

    // تنظیم وضعیت VPN برای شبیه‌سازی ترافیک
    void setVpnActive(bool active)
    {
        QMutexLocker locker(&mutex);
        vpnActive = active;
    }

    // دریافت آمار کلی
    quint64 getTotalUpload() const { return totalUpload; }
    quint64 getTotalDownload() const { return totalDownload; }

private slots:
    void updateConnections()
    {
        if (isUpdating)
            return;
        isUpdating = true;

        QMutexLocker locker(&mutex);

        // اگر VPN فعال است، ترافیک کلی شبیه‌سازی شود
        if (vpnActive)
        {
            // افزایش تصادفی بین 0 تا 50 کیلوبایت برای هر دو جهت
            quint64 upInc = rand() % 51200;
            quint64 downInc = rand() % 51200;
            totalUpload += upInc;
            totalDownload += downInc;
        }

        // به‌روزرسانی ترافیک هر برنامه فعال
        for (auto &app : managedApps)
        {
            if (app.pid != 0 && app.useProxy && vpnActive)
            {
                // افزایش تصادفی بین 0 تا 10 کیلوبایت
                quint64 upInc = rand() % 10240;
                quint64 downInc = rand() % 10240;
                app.totalUpload += upInc;
                app.totalDownload += downInc;
                // آمار کلی هم از قبل افزایش یافته، پس نیازی به جمع مجدد نیست
            }
        }
        locker.unlock();

        emit managedAppsUpdated(managedApps);
        emit overallStatsUpdated(totalUpload, totalDownload);

        updateCounter++;
        isUpdating = false;
    }

    void monitorApplications()
    {
        QMutexLocker locker(&mutex);
        if (managedApps.isEmpty())
            return;

        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE)
            return;

        PROCESSENTRY32 pe;
        pe.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(hSnapshot, &pe))
        {
            do
            {
                QString processName = QString::fromWCharArray(pe.szExeFile);
                quint32 pid = pe.th32ProcessID;

                for (auto &app : managedApps)
                {
                    if (app.forceProxy && app.useProxy && !app.path.isEmpty())
                    {
                        QString appFileName = QFileInfo(app.path).fileName();
                        if (processName.compare(appFileName, Qt::CaseInsensitive) == 0)
                        {
                            if (app.pid != pid)
                            {
                                app.pid = pid;
                                emit processDetected(app.name, pid);
                            }
                        }
                    }
                }

            } while (Process32Next(hSnapshot, &pe));
        }

        CloseHandle(hSnapshot);
    }

signals:
    void trafficUpdated(const QMap<quint32, ConnectionInfo> &connections);
    void managedAppsUpdated(const QMap<QString, ManagedApp> &managedApps);
    void processDetected(const QString &appName, quint32 pid);
    void overallStatsUpdated(quint64 totalUp, quint64 totalDown);
};

// کلاس مدیریت تست پروکسی خودکار با HTTP Request
class AutoProxyTestManager : public QObject
{
    Q_OBJECT
private:
    QTimer *testTimer;
    QTimer *periodicTestTimer;
    QTimer *retryTimer;
    QTimer *currentProxyTimer; // تایمر برای تست پروکسی جاری
    QList<ProxyItem> proxyList;
    int currentTestIndex;
    bool isTesting;
    int testDelay;
    QString testUrl;
    static const int TEST_DELAY = 1000;
    static const int PERIODIC_TEST_INTERVAL = 300000; // 5 دقیقه (برای تست کامل)
    int retryInterval;
    volatile bool isShuttingDown;
    mutable QMutex mutex;
    QMap<QString, QPointer<QNetworkAccessManager>> activeTests;
    QString currentProxyName; // نام پروکسی جاری
    bool hasCurrentProxy;

public:
    AutoProxyTestManager(QObject *parent = nullptr) : QObject(parent), currentTestIndex(0), isTesting(false), testDelay(TEST_DELAY), retryInterval(5000), isShuttingDown(false), hasCurrentProxy(false)
    {
        testTimer = new QTimer(this);
        testTimer->setSingleShot(true);
        connect(testTimer, &QTimer::timeout, this, &AutoProxyTestManager::testNextProxy);

        periodicTestTimer = new QTimer(this);
        connect(periodicTestTimer, &QTimer::timeout, this, &AutoProxyTestManager::startPeriodicTesting);
        periodicTestTimer->start(PERIODIC_TEST_INTERVAL);

        retryTimer = new QTimer(this);
        retryTimer->setSingleShot(false);
        connect(retryTimer, &QTimer::timeout, this, &AutoProxyTestManager::retryAllProxies);
        retryTimer->start(retryInterval);

        // تایمر برای تست پروکسی جاری
        currentProxyTimer = new QTimer(this);
        currentProxyTimer->setSingleShot(false);
        connect(currentProxyTimer, &QTimer::timeout, this, &AutoProxyTestManager::testCurrentProxy);

        // URL مطمئن‌تر برای تست
        testUrl = "http://connectivitycheck.android.com/generate_204";
    }

    // Getters برای استفاده در ذخیره‌سازی تنظیمات
    QString getTestUrl() const
    {
        QMutexLocker locker(&mutex);
        return testUrl;
    }

    int getRetryInterval() const
    {
        QMutexLocker locker(&mutex);
        return retryInterval;
    }

    void shutdown()
    {
        QMutexLocker locker(&mutex);
        isShuttingDown = true;

        if (testTimer)
            testTimer->stop();
        if (periodicTestTimer)
            periodicTestTimer->stop();
        if (retryTimer)
            retryTimer->stop();
        if (currentProxyTimer)
            currentProxyTimer->stop();

        for (auto &manager : activeTests)
        {
            if (manager)
            {
                manager->deleteLater();
            }
        }
        activeTests.clear();
    }

    void setProxyList(const QList<ProxyItem> &proxies)
    {
        QMutexLocker locker(&mutex);
        proxyList = proxies;
        // اگر پروکسی جاری در لیست جدید نیست، آن را پاک کن
        if (!currentProxyName.isEmpty())
        {
            bool found = false;
            for (const ProxyItem &p : proxyList)
            {
                if (p.name == currentProxyName)
                {
                    found = true;
                    break;
                }
            }
            if (!found)
            {
                currentProxyName.clear();
                hasCurrentProxy = false;
                currentProxyTimer->stop();
            }
        }
    }

    void setTestUrl(const QString &url)
    {
        QMutexLocker locker(&mutex);
        testUrl = url;
    }

    void setRetryInterval(int interval)
    {
        QMutexLocker locker(&mutex);
        retryInterval = interval;
        if (retryTimer)
        {
            retryTimer->setInterval(interval);
        }
        if (currentProxyTimer && hasCurrentProxy)
        {
            currentProxyTimer->setInterval(interval);
        }
    }

    void setCurrentProxy(const QString &name)
    {
        QMutexLocker locker(&mutex);
        if (isShuttingDown)
            return;

        if (name.isEmpty())
        {
            // پروکسی جاری غیرفعال شد
            currentProxyName.clear();
            hasCurrentProxy = false;
            currentProxyTimer->stop();
        }
        else
        {
            currentProxyName = name;
            hasCurrentProxy = true;
            currentProxyTimer->setInterval(retryInterval);
            currentProxyTimer->start();
            // بلافاصله یکبار تست کن
            locker.unlock();
            testProxy(name);
        }
    }

    void startTesting()
    {
        QMutexLocker locker(&mutex);
        if (isShuttingDown || proxyList.isEmpty() || isTesting)
            return;

        isTesting = true;
        currentTestIndex = 0;
        locker.unlock();
        emit testStarted(proxyList.size());
        QTimer::singleShot(0, this, &AutoProxyTestManager::testNextProxy);
    }

    void startPeriodicTesting()
    {
        QMutexLocker locker(&mutex);
        if (isShuttingDown)
            return;
        locker.unlock();
        if (!proxyList.isEmpty())
        {
            startTesting();
        }
    }

    void stopTesting()
    {
        QMutexLocker locker(&mutex);
        isTesting = false;
        if (testTimer)
        {
            testTimer->stop();
        }
    }

    // کنترل فعال/غیرفعال بودن همه تایمرها
    void setActive(bool active)
    {
        QMutexLocker locker(&mutex);
        if (active)
        {
            if (!isTesting && !proxyList.isEmpty())
            {
                isTesting = true;
                currentTestIndex = 0;
                QTimer::singleShot(0, this, &AutoProxyTestManager::testNextProxy);
            }
            if (retryTimer)
                retryTimer->start(retryInterval);
            if (currentProxyTimer && hasCurrentProxy)
                currentProxyTimer->start(retryInterval);
        }
        else
        {
            isTesting = false;
            if (testTimer)
                testTimer->stop();
            if (retryTimer)
                retryTimer->stop();
            if (currentProxyTimer)
                currentProxyTimer->stop();
        }
    }

    void testProxy(const QString &proxyName)
    {
        QMutexLocker locker(&mutex);
        if (isShuttingDown)
            return;

        ProxyItem proxy;
        bool found = false;
        for (const ProxyItem &p : proxyList)
        {
            if (p.name == proxyName)
            {
                proxy = p;
                found = true;
                break;
            }
        }

        if (!found)
            return;

        if (activeTests.contains(proxyName) && activeTests[proxyName])
        {
            activeTests[proxyName]->deleteLater();
            activeTests.remove(proxyName);
        }

        QNetworkAccessManager *manager = new QNetworkAccessManager();
        activeTests[proxyName] = manager;

        QElapsedTimer timer;
        timer.start();

        QNetworkProxy networkProxy;
        if (proxy.type == "http")
        {
            networkProxy.setType(QNetworkProxy::HttpProxy);
        }
        else if (proxy.type == "socks5")
        {
            networkProxy.setType(QNetworkProxy::Socks5Proxy);
        }
        else
        {
            networkProxy.setType(QNetworkProxy::NoProxy);
        }

        networkProxy.setHostName(proxy.address);
        networkProxy.setPort(proxy.port);

        if (!proxy.username.isEmpty())
        {
            networkProxy.setUser(proxy.username);
        }
        if (!proxy.password.isEmpty())
        {
            networkProxy.setPassword(proxy.password);
        }

        manager->setProxy(networkProxy);

        QNetworkRequest request;
        request.setUrl(QUrl(testUrl));
        request.setHeader(QNetworkRequest::UserAgentHeader, "VPN-Proxy-Manager-Test/1.0");
        request.setTransferTimeout(10000); // افزایش تایم‌اوت به 10 ثانیه

        QNetworkReply *reply = manager->get(request);

        QPointer<QNetworkReply> replyPtr(reply);
        QPointer<QNetworkAccessManager> managerPtr(manager);
        QString proxyNameCopy = proxyName;

        connect(reply, &QNetworkReply::finished, this, [this, replyPtr, managerPtr, proxyNameCopy, timer]()
                {
            QMutexLocker locker(&mutex);
            if (isShuttingDown) {
                if (replyPtr) replyPtr->deleteLater();
                if (managerPtr) managerPtr->deleteLater();
                activeTests.remove(proxyNameCopy);
                return;
            }
            
            int delay = -1;
            if (replyPtr && replyPtr->error() == QNetworkReply::NoError) {
                delay = timer.elapsed();
            }
            
            if (replyPtr) replyPtr->deleteLater();
            if (managerPtr) managerPtr->deleteLater();
            activeTests.remove(proxyNameCopy);
            
            locker.unlock();
            emit proxyTested(proxyNameCopy, delay);
            
            // اگر این پروکسی جاری بود و غیرفعال شد، سیگنال بده
            if (hasCurrentProxy && proxyNameCopy == currentProxyName && (delay < 0 || delay >= 5000)) {
                emit currentProxyFailed();
            } });

        // تایم‌اوت طولانی‌تر برای قطع درخواست‌های خیلی کند
        QTimer::singleShot(15000, this, [this, replyPtr, managerPtr, proxyNameCopy]()
                           {
            QMutexLocker locker(&mutex);
            if (isShuttingDown) return;
            
            if (replyPtr && !replyPtr->isFinished()) {
                replyPtr->abort();
                replyPtr->deleteLater();
                if (managerPtr) managerPtr->deleteLater();
                activeTests.remove(proxyNameCopy);
                locker.unlock();
                emit proxyTested(proxyNameCopy, -1);
                
                if (hasCurrentProxy && proxyNameCopy == currentProxyName) {
                    emit currentProxyFailed();
                }
            } });
    }

    void retryAllProxies()
    {
        QMutexLocker locker(&mutex);
        if (isShuttingDown || proxyList.isEmpty())
            return;

        QDateTime now = QDateTime::currentDateTime();

        QStringList toTest;
        for (const ProxyItem &proxy : proxyList)
        {
            // همه پروکسی‌ها را تست کن، ولی اگر آخرین تست کمتر از نصف retryInterval پیش بوده، صرف‌نظر کن
            if (!proxy.lastTestTime.isValid() ||
                proxy.lastTestTime.secsTo(now) > retryInterval / 1000 / 2)
            {
                toTest.append(proxy.name);
            }
        }

        locker.unlock();
        for (const QString &name : toTest)
        {
            testProxy(name);
        }
    }

private slots:
    void testNextProxy()
    {
        QMutexLocker locker(&mutex);
        if (isShuttingDown || !isTesting)
            return;

        if (currentTestIndex >= proxyList.size())
        {
            isTesting = false;
            locker.unlock();
            emit testFinished();
            return;
        }

        QString proxyName = proxyList[currentTestIndex].name;
        currentTestIndex++;

        locker.unlock();
        testProxy(proxyName);

        if (currentTestIndex < proxyList.size())
        {
            testTimer->start(testDelay);
        }
    }

    void testCurrentProxy()
    {
        if (!hasCurrentProxy || currentProxyName.isEmpty())
            return;
        testProxy(currentProxyName);
    }

signals:
    void proxyTested(const QString &name, int delay);
    void testStarted(int totalCount);
    void testFinished();
    void currentProxyFailed(); // سیگنال برای شکست پروکسی جاری
};

// کلاس مدیریت sing-box
class SingBoxManager : public QObject
{
    Q_OBJECT
private:
    QProcess *singBoxProcess;
    QString configPath;
    QString singBoxPath;
    bool isRunning;
    QString currentConfig;
    int localHttpPort;
    int localSocksPort;
    ProxyItem currentProxy;
    SingBoxConfig config;
    QTimer *autoRestartTimer;
    bool isRestarting;
    static SingBoxManager *instance;
    bool isStarting;
    bool restartScheduled;
    static QMutex staticMutex;
    bool connectionsEstablished;
    bool isStopping;

    SingBoxManager(QObject *parent = nullptr) : QObject(parent), isRunning(false), localHttpPort(10809), localSocksPort(10808), isRestarting(false), isStarting(false), restartScheduled(false), connectionsEstablished(false), isStopping(false)
    {
        singBoxProcess = new QProcess(this);

        singBoxPath = QCoreApplication::applicationDirPath() + "/sing-box.exe";

        setupConnections();
    }

    void setupConnections()
    {
        if (!connectionsEstablished)
        {
            connect(singBoxProcess, QOverload<int, QProcess::ExitStatus>::of(&QProcess::finished),
                    this, &SingBoxManager::onProcessFinished);

            connect(singBoxProcess, &QProcess::readyReadStandardOutput, this, &SingBoxManager::onReadyRead);
            connect(singBoxProcess, &QProcess::readyReadStandardError, this, &SingBoxManager::onReadyRead);

            autoRestartTimer = new QTimer(this);
            autoRestartTimer->setSingleShot(true);
            connect(autoRestartTimer, &QTimer::timeout, this, &SingBoxManager::onAutoRestart);

            connectionsEstablished = true;
        }
    }

public:
    static SingBoxManager *getInstance(QObject *parent = nullptr)
    {
        QMutexLocker locker(&staticMutex);
        if (!instance)
        {
            instance = new SingBoxManager(parent);
        }
        return instance;
    }

    ~SingBoxManager()
    {
        stop();
    }

    bool isAvailable()
    {
        return QFile::exists(singBoxPath);
    }

    QString getSingBoxPath() const
    {
        return singBoxPath;
    }

    void setLocalPorts(int httpPort, int socksPort)
    {
        localHttpPort = httpPort;
        localSocksPort = socksPort;
    }

    int getLocalHttpPort() const
    {
        return localHttpPort;
    }

    int getLocalSocksPort() const
    {
        return localSocksPort;
    }

    bool isActive() const
    {
        return isRunning;
    }

    ProxyItem getCurrentProxy() const
    {
        return currentProxy;
    }

    SingBoxConfig getConfig() const
    {
        return config;
    }

    void setConfig(const SingBoxConfig &newConfig)
    {
        config = newConfig;
        localHttpPort = config.httpPort;
        localSocksPort = config.socksPort;
    }

    // بررسی وضعیت مشغول بودن برای جلوگیری از تداخل
    bool isBusy() const
    {
        return isStarting || isStopping || isRestarting;
    }

    void restartWithBestProxy()
    {
        if (isRestarting || isStarting || isStopping)
        {
            emit logMessage("⚠️ Restart ignored - operation in progress");
            return;
        }

        isRestarting = true;

        emit logMessage("🔄 Restarting with best proxy...");

        if (isRunning)
        {
            stop();
            QTimer::singleShot(2000, this, [this]()
                               {
                if (!isRestarting) {
                    return;
                }
                emit requestBestProxyStart();
                isRestarting = false; });
        }
        else
        {
            emit requestBestProxyStart();
            isRestarting = false;
        }
    }

    bool startWithBestProxy(const QList<ProxyItem> &proxies)
    {
        if (isRunning || isStarting || isStopping)
        {
            emit logMessage("⚠️ Sing-Box is already running, starting or stopping");
            return true;
        }

        isStarting = true;
        restartScheduled = false;

        if (!isAvailable())
        {
            emit logMessage("❌ sing-box.exe not found");
            isStarting = false;
            return false;
        }

        if (proxies.isEmpty())
        {
            emit logMessage("❌ No proxies in list");
            isStarting = false;
            return false;
        }

        QList<ProxyItem> activeProxies;
        for (const ProxyItem &proxy : proxies)
        {
            if (proxy.isActive && proxy.delay > 0 && proxy.delay < 5000)
            {
                activeProxies.append(proxy);
            }
        }

        if (activeProxies.isEmpty())
        {
            emit logMessage("❌ No active proxy found");
            isStarting = false;
            return false;
        }

        ProxyItem bestProxy;
        int bestDelay = INT_MAX;

        for (const ProxyItem &proxy : activeProxies)
        {
            if (proxy.delay < bestDelay)
            {
                bestDelay = proxy.delay;
                bestProxy = proxy;
            }
        }

        currentProxy = bestProxy;

        emit logMessage(QString("📢 Selected best proxy: %1 (Delay: %2 ms)").arg(bestProxy.name).arg(bestDelay));

        QString configStr = generateConfig(bestProxy);
        if (configStr.isEmpty())
        {
            emit logMessage("❌ Failed to generate config");
            isStarting = false;
            return false;
        }

        QString appDirPath = QCoreApplication::applicationDirPath();
        configPath = appDirPath + "/singbox_config.json";

        QFile file(configPath);
        if (!file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            emit logMessage("❌ Failed to write config file");
            isStarting = false;
            return false;
        }

        QTextStream stream(&file);
        stream << configStr;
        file.close();

        currentConfig = configStr;

        emit logMessage("🚀 Starting sing-box process...");

        QStringList arguments;
        arguments << "run" << "-c" << configPath;

        singBoxProcess->start(singBoxPath, arguments);

        if (!singBoxProcess->waitForStarted(5000))
        {
            emit logMessage("❌ Failed to start sing-box: " + singBoxProcess->errorString());
            isStarting = false;
            return false;
        }

        isRunning = true;
        isStarting = false;
        emit statusChanged(true);
        emit logMessage(QString("✅ Sing-Box started with proxy: %1").arg(bestProxy.name));

        QString listenAddr = this->config.allowLan ? "0.0.0.0" : "127.0.0.1";
        emit logMessage(QString("📢 HTTP: %1:%2, SOCKS5: %1:%3").arg(listenAddr).arg(localHttpPort).arg(localSocksPort));

        return true;
    }

    void stop()
    {
        if (isStopping)
        {
            return;
        }

        isStopping = true;

        if (!isRunning)
        {
            isStopping = false;
            return;
        }

        emit logMessage("🛑 Stopping sing-box...");

        singBoxProcess->terminate();

        if (!singBoxProcess->waitForFinished(3000))
        {
            singBoxProcess->kill();
            singBoxProcess->waitForFinished(1000);
        }

        isRunning = false;
        isStarting = false;
        restartScheduled = false;
        autoRestartTimer->stop();

        emit statusChanged(false);
        emit logMessage("✅ Sing-Box stopped");

        isStopping = false;
    }

signals:
    void statusChanged(bool running);
    void logMessage(const QString &message);
    void outputReceived(const QString &output);
    void requestBestProxyStart();

private slots:
    void onProcessFinished(int exitCode, QProcess::ExitStatus exitStatus)
    {
        bool wasRunning = isRunning;
        bool shouldRestart = false;

        isRunning = false;
        isStarting = false;

        shouldRestart = (wasRunning && !restartScheduled && !isStopping);
        if (shouldRestart)
        {
            restartScheduled = true;
        }

        emit statusChanged(false);

        if (exitStatus == QProcess::CrashExit)
        {
            emit logMessage("❌ Sing-Box process crashed");
        }
        else
        {
            emit logMessage(QString("ℹ️ Sing-Box finished (code: %1)").arg(exitCode));
        }

        if (shouldRestart)
        {
            emit logMessage("🔄 Auto-restart in 5 seconds...");
            autoRestartTimer->start(5000);
        }
    }

    void onReadyRead()
    {
        QString output = QString::fromLocal8Bit(singBoxProcess->readAllStandardOutput());
        if (!output.isEmpty())
        {
            QStringList lines = output.split("\n");
            for (const QString &line : lines)
            {
                if (!line.trimmed().isEmpty())
                {
                    emit outputReceived(line);
                }
            }
        }

        QString error = QString::fromLocal8Bit(singBoxProcess->readAllStandardError());
        if (!error.isEmpty())
        {
            QStringList lines = error.split("\n");
            for (const QString &line : lines)
            {
                if (!line.trimmed().isEmpty())
                {
                    emit outputReceived("[Error] " + line);
                }
            }
        }
    }

    void onAutoRestart()
    {
        bool shouldRestart = false;

        if (!isRunning && !isStarting && restartScheduled && !isStopping)
        {
            restartScheduled = false;
            shouldRestart = true;
        }

        if (shouldRestart)
        {
            emit requestBestProxyStart();
        }
    }

private:
    QString generateConfig(const ProxyItem &proxy)
    {
        QJsonObject configObj;

        QJsonObject log;
        log["disabled"] = config.logDisabled;
        log["level"] = config.logLevel;
        if (!config.logOutput.isEmpty())
        {
            log["output"] = config.logOutput;
        }
        configObj["log"] = log;

        QJsonObject dns;
        QJsonArray servers;

        for (const QString &dnsServer : config.dnsServers)
        {
            QJsonObject server;
            QString serverTag = "dns-" + QString(dnsServer).replace(".", "");
            server["tag"] = serverTag;
            server["address"] = dnsServer;
            server["detour"] = "direct";
            servers.append(server);
        }

        QJsonObject localDns;
        localDns["tag"] = "local-dns";
        localDns["address"] = "local";
        localDns["detour"] = "direct";
        servers.append(localDns);

        dns["servers"] = servers;
        dns["final"] = "local-dns";
        configObj["dns"] = dns;

        QJsonArray inbounds;

        QString listenAddr = config.allowLan ? "0.0.0.0" : "127.0.0.1";

        if (config.enableHttp)
        {
            QJsonObject httpInbound;
            httpInbound["type"] = "http";
            httpInbound["tag"] = "http-in";
            httpInbound["listen"] = listenAddr;
            httpInbound["listen_port"] = localHttpPort;
            // اضافه کردن احراز هویت اگر username/password تنظیم شده باشد
            if (!config.outboundUsername.isEmpty() || !config.outboundPassword.isEmpty())
            {
                QJsonArray users;
                QJsonObject user;
                user["username"] = config.outboundUsername;
                user["password"] = config.outboundPassword;
                users.append(user);
                httpInbound["users"] = users;
            }
            inbounds.append(httpInbound);
        }

        if (config.enableSocks)
        {
            QJsonObject socksInbound;
            socksInbound["type"] = "socks";
            socksInbound["tag"] = "socks-in";
            socksInbound["listen"] = listenAddr;
            socksInbound["listen_port"] = localSocksPort;
            // اضافه کردن احراز هویت اگر username/password تنظیم شده باشد
            if (!config.outboundUsername.isEmpty() || !config.outboundPassword.isEmpty())
            {
                QJsonArray users;
                QJsonObject user;
                user["username"] = config.outboundUsername;
                user["password"] = config.outboundPassword;
                users.append(user);
                socksInbound["users"] = users;
            }
            inbounds.append(socksInbound);
        }

        configObj["inbounds"] = inbounds;

        QJsonArray outbounds;

        QJsonObject directOutbound;
        directOutbound["type"] = "direct";
        directOutbound["tag"] = "direct";
        outbounds.append(directOutbound);

        QJsonObject blockOutbound;
        blockOutbound["type"] = "block";
        blockOutbound["tag"] = "block";
        outbounds.append(blockOutbound);

        QJsonObject proxyOutbound;
        proxyOutbound["tag"] = "proxy";

        if (proxy.type == "http")
        {
            proxyOutbound["type"] = "http";
            proxyOutbound["server"] = proxy.address;
            proxyOutbound["server_port"] = proxy.port;
            if (!proxy.username.isEmpty())
            {
                proxyOutbound["username"] = proxy.username;
            }
            if (!proxy.password.isEmpty())
            {
                proxyOutbound["password"] = proxy.password;
            }
        }
        else if (proxy.type == "socks5")
        {
            proxyOutbound["type"] = "socks";
            proxyOutbound["server"] = proxy.address;
            proxyOutbound["server_port"] = proxy.port;
            proxyOutbound["version"] = "5";
            if (!proxy.username.isEmpty())
            {
                proxyOutbound["username"] = proxy.username;
            }
            if (!proxy.password.isEmpty())
            {
                proxyOutbound["password"] = proxy.password;
            }
        }
        else if (proxy.type == "shadowsocks")
        {
            proxyOutbound["type"] = "shadowsocks";
            proxyOutbound["server"] = proxy.address;
            proxyOutbound["server_port"] = proxy.port;
            proxyOutbound["method"] = proxy.method.isEmpty() ? "aes-256-gcm" : proxy.method;
            proxyOutbound["password"] = proxy.password;
        }
        else if (proxy.type == "vmess")
        {
            proxyOutbound["type"] = "vmess";
            proxyOutbound["server"] = proxy.address;
            proxyOutbound["server_port"] = proxy.port;
            proxyOutbound["uuid"] = proxy.uuid.isEmpty() ? proxy.username : proxy.uuid;
            proxyOutbound["security"] = proxy.encryption.isEmpty() ? "auto" : proxy.encryption;
            proxyOutbound["alter_id"] = 0;

            if (proxy.tls)
            {
                QJsonObject tls;
                tls["enabled"] = true;
                tls["server_name"] = proxy.address;
                tls["insecure"] = true;
                proxyOutbound["tls"] = tls;
            }

            if (!proxy.path.isEmpty())
            {
                QJsonObject transport;
                transport["type"] = "ws";
                QJsonObject wsOptions;
                wsOptions["path"] = proxy.path;
                transport["ws_options"] = wsOptions;
                proxyOutbound["transport"] = transport;
            }
        }
        else if (proxy.type == "vless")
        {
            proxyOutbound["type"] = "vless";
            proxyOutbound["server"] = proxy.address;
            proxyOutbound["server_port"] = proxy.port;
            proxyOutbound["uuid"] = proxy.uuid.isEmpty() ? proxy.username : proxy.uuid;

            if (proxy.tls)
            {
                QJsonObject tls;
                tls["enabled"] = true;
                tls["server_name"] = proxy.address;
                tls["insecure"] = true;
                proxyOutbound["tls"] = tls;
            }

            if (!proxy.path.isEmpty())
            {
                QJsonObject transport;
                transport["type"] = "ws";
                QJsonObject wsOptions;
                wsOptions["path"] = proxy.path;
                transport["ws_options"] = wsOptions;
                proxyOutbound["transport"] = transport;
            }
        }
        else if (proxy.type == "trojan")
        {
            proxyOutbound["type"] = "trojan";
            proxyOutbound["server"] = proxy.address;
            proxyOutbound["server_port"] = proxy.port;
            proxyOutbound["password"] = proxy.password;

            if (proxy.tls)
            {
                QJsonObject tls;
                tls["enabled"] = true;
                tls["server_name"] = proxy.address;
                tls["insecure"] = true;
                proxyOutbound["tls"] = tls;
            }
        }
        else
        {
            return QString();
        }

        outbounds.append(proxyOutbound);
        configObj["outbounds"] = outbounds;

        QJsonObject route;
        QJsonArray rules;

        QJsonObject dnsRule;
        dnsRule["protocol"] = "dns";
        dnsRule["outbound"] = "direct";
        rules.append(dnsRule);

        QJsonObject defaultRule;
        defaultRule["outbound"] = "proxy";
        rules.append(defaultRule);

        route["rules"] = rules;
        route["final"] = "proxy";
        route["auto_detect_interface"] = config.autoDetectInterface;
        configObj["route"] = route;

        QJsonDocument doc(configObj);
        return doc.toJson(QJsonDocument::Indented);
    }
};

SingBoxManager *SingBoxManager::instance = nullptr;
QMutex SingBoxManager::staticMutex;

// کلاس مدیریت VPN
class VpnProxyManager : public QObject
{
    Q_OBJECT
private:
    SingBoxManager *singBox;
    bool isConnected;
    bool isStarting;
    int localHttpPort;
    int localSocksPort;
    ProxyItem currentProxyItem;
    bool connectionsEstablished;
    bool isDisconnecting;

public:
    VpnProxyManager(QObject *parent = nullptr) : QObject(parent), isConnected(false), isStarting(false), localHttpPort(10809), localSocksPort(10808), connectionsEstablished(false), isDisconnecting(false)
    {
        singBox = SingBoxManager::getInstance(this);
    }

    void setupConnections()
    {
        if (!connectionsEstablished)
        {
            connect(singBox, &SingBoxManager::statusChanged, this, &VpnProxyManager::onSingBoxStatusChanged);
            connect(singBox, &SingBoxManager::logMessage, this, &VpnProxyManager::logMessage);
            connectionsEstablished = true;
        }
    }

    bool startWithBestProxy(const QList<ProxyItem> &proxies, int httpPort = 10809, int socksPort = 10808)
    {
        if (isStarting || isConnected || isDisconnecting)
        {
            emit logMessage("⚠️ Already starting, connected or disconnecting");
            return true;
        }

        isStarting = true;
        localHttpPort = httpPort;
        localSocksPort = socksPort;
        singBox->setLocalPorts(httpPort, socksPort);

        emit logMessage("🚀 Starting with best proxy...");

        bool result = singBox->startWithBestProxy(proxies);

        if (result)
        {
            isConnected = true;
            currentProxyItem = singBox->getCurrentProxy();
            emit statusChanged(true);
            isStarting = false;
            return true;
        }

        isStarting = false;
        return false;
    }

    void disconnect()
    {
        if (isDisconnecting)
        {
            return;
        }

        if (!isConnected)
        {
            return;
        }

        isDisconnecting = true;

        emit logMessage("🛑 Disconnecting...");
        singBox->stop();

        isDisconnecting = false;
    }

    bool getIsConnected() const
    {
        return isConnected;
    }

    SingBoxManager *getSingBoxManager()
    {
        return singBox;
    }

    int getLocalHttpPort() const
    {
        return localHttpPort;
    }

    int getLocalSocksPort() const
    {
        return localSocksPort;
    }

    ProxyItem getCurrentProxyItem() const
    {
        return currentProxyItem;
    }

signals:
    void statusChanged(bool connected);
    void logMessage(const QString &msg);

private slots:
    void onSingBoxStatusChanged(bool running)
    {
        if (running != isConnected)
        {
            isConnected = running;
            if (!running)
            {
                isStarting = false;
            }
            emit statusChanged(running);
        }
    }
};

// کلاس مدیریت تنظیمات فایل
class ConfigManager : public QObject
{
    Q_OBJECT
private:
    QString configFilePath;
    QString proxiesFilePath;
    QString singBoxConfigPath;

public:
    ConfigManager(QObject *parent = nullptr) : QObject(parent)
    {
        QString appDir = QCoreApplication::applicationDirPath();
        configFilePath = appDir + "/config.txt";
        proxiesFilePath = appDir + "/proxies.json";
        singBoxConfigPath = appDir + "/singbox_settings.json";
    }

    QString getConfigFilePath() const
    {
        return configFilePath;
    }

    QString getProxiesFilePath() const
    {
        return proxiesFilePath;
    }

    QString getSingBoxConfigPath() const
    {
        return singBoxConfigPath;
    }

    bool saveConfig(const QMap<QString, QVariant> &config)
    {
        QFile file(configFilePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            QTextStream stream(&file);

            stream << "[LOCAL]\n";
            stream << "http_port=" << config.value("local/http_port", "10809").toString() << "\n";
            stream << "socks_port=" << config.value("local/socks_port", "10808").toString() << "\n";
            stream << "auto_start_vpn=" << (config.value("auto_start_vpn", false).toBool() ? "1" : "0") << "\n\n";

            stream << "[APPLICATIONS]\n";
            QList<QVariant> apps = config.value("managedApps").toList();
            for (const QVariant &appVar : apps)
            {
                QMap<QString, QVariant> app = appVar.toMap();
                stream << "app_name=" << app.value("name", "").toString() << "\n";
                stream << "app_path=" << app.value("path", "").toString() << "\n";
                stream << "app_useProxy=" << (app.value("useProxy", true).toBool() ? "1" : "0") << "\n";
                stream << "app_forceProxy=" << (app.value("forceProxy", true).toBool() ? "1" : "0") << "\n";
                stream << "---\n";
            }

            file.close();
            return true;
        }
        return false;
    }

    QMap<QString, QVariant> loadConfig()
    {
        QMap<QString, QVariant> config;

        QFile file(configFilePath);
        if (!file.exists() || !file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            config["local/http_port"] = "10809";
            config["local/socks_port"] = "10808";
            config["auto_start_vpn"] = false;
            config["managedApps"] = QVariantList();
            return config;
        }

        QTextStream stream(&file);
        QString currentSection;
        QVariantList appsList;
        QMap<QString, QVariant> currentApp;

        while (!stream.atEnd())
        {
            QString line = stream.readLine().trimmed();

            if (line.isEmpty())
                continue;

            if (line.startsWith("[") && line.endsWith("]"))
            {
                currentSection = line.mid(1, line.length() - 2);
            }
            else if (line.contains("="))
            {
                QString key = line.section('=', 0, 0).trimmed();
                QString value = line.section('=', 1).trimmed();

                if (currentSection == "LOCAL")
                {
                    if (key == "http_port")
                        config["local/http_port"] = value;
                    else if (key == "socks_port")
                        config["local/socks_port"] = value;
                    else if (key == "auto_start_vpn")
                        config["auto_start_vpn"] = (value == "1" || value.toLower() == "true");
                }
                else if (currentSection == "APPLICATIONS")
                {
                    if (key == "app_name")
                        currentApp["name"] = value;
                    else if (key == "app_path")
                        currentApp["path"] = value;
                    else if (key == "app_useProxy")
                        currentApp["useProxy"] = (value == "1" || value.toLower() == "true");
                    else if (key == "app_forceProxy")
                        currentApp["forceProxy"] = (value == "1" || value.toLower() == "true");
                    else if (key == "---")
                    {
                        if (!currentApp.isEmpty())
                        {
                            appsList.append(currentApp);
                            currentApp.clear();
                        }
                    }
                }
            }
        }

        if (!currentApp.isEmpty())
        {
            appsList.append(currentApp);
        }

        config["managedApps"] = appsList;
        file.close();

        return config;
    }

    bool saveSingBoxConfig(const SingBoxConfig &config)
    {
        QJsonObject obj;
        obj["log_level"] = config.logLevel;
        obj["log_disabled"] = config.logDisabled;
        obj["log_output"] = config.logOutput;
        obj["dns_server"] = config.dnsServer;
        obj["socks_port"] = config.socksPort;
        obj["http_port"] = config.httpPort;
        obj["auto_detect_interface"] = config.autoDetectInterface;
        obj["enable_socks"] = config.enableSocks;
        obj["enable_http"] = config.enableHttp;
        obj["allow_lan"] = config.allowLan;
        obj["outbound_username"] = config.outboundUsername;
        obj["outbound_password"] = config.outboundPassword;
        obj["latency_test_url"] = config.latencyTestUrl;
        obj["retry_interval"] = config.retryInterval;

        QJsonArray dnsServers;
        for (const QString &server : config.dnsServers)
        {
            if (!dnsServers.contains(server))
            {
                dnsServers.append(server);
            }
        }
        obj["dns_servers"] = dnsServers;

        QJsonDocument doc(obj);

        QFile file(singBoxConfigPath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            file.write(doc.toJson(QJsonDocument::Indented));
            file.close();
            return true;
        }

        return false;
    }

    SingBoxConfig loadSingBoxConfig()
    {
        SingBoxConfig config;

        QFile file(singBoxConfigPath);
        if (!file.exists() || !file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            return config;
        }

        QByteArray data = file.readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);

        if (!doc.isObject())
        {
            return config;
        }

        QJsonObject obj = doc.object();

        config.logLevel = obj["log_level"].toString("info");
        config.logDisabled = obj["log_disabled"].toBool(false);
        config.logOutput = obj["log_output"].toString("");
        config.dnsServer = obj["dns_server"].toString("8.8.8.8");
        config.socksPort = obj["socks_port"].toInt(10808);
        config.httpPort = obj["http_port"].toInt(10809);
        config.autoDetectInterface = obj["auto_detect_interface"].toBool(true);
        config.enableSocks = obj["enable_socks"].toBool(true);
        config.enableHttp = obj["enable_http"].toBool(true);
        config.allowLan = obj["allow_lan"].toBool(false);
        config.outboundUsername = obj["outbound_username"].toString("");
        config.outboundPassword = obj["outbound_password"].toString("");
        config.latencyTestUrl = obj["latency_test_url"].toString("http://connectivitycheck.android.com/generate_204");
        config.retryInterval = obj["retry_interval"].toInt(5000);

        QJsonArray dnsServers = obj["dns_servers"].toArray();
        if (!dnsServers.isEmpty())
        {
            config.dnsServers.clear();
            for (const QJsonValue &val : dnsServers)
            {
                QString server = val.toString();
                if (!config.dnsServers.contains(server))
                {
                    config.dnsServers.append(server);
                }
            }
        }

        return config;
    }

    bool saveProxies(const QList<ProxyItem> &proxies)
    {
        QJsonArray proxyArray;

        for (const ProxyItem &proxy : proxies)
        {
            QJsonObject obj;
            obj["name"] = proxy.name;
            obj["type"] = proxy.type;
            obj["address"] = proxy.address;
            obj["port"] = proxy.port;
            obj["username"] = proxy.username;
            obj["password"] = proxy.password;
            obj["uuid"] = proxy.uuid;
            obj["method"] = proxy.method;
            obj["path"] = proxy.path;
            obj["encryption"] = proxy.encryption;
            obj["tls"] = proxy.tls;
            obj["isActive"] = proxy.isActive;
            obj["delay"] = proxy.delay;
            obj["lastTestTime"] = proxy.lastTestTime.toString(Qt::ISODate);
            obj["lastSuccessTime"] = proxy.lastSuccessTime.toString(Qt::ISODate);
            obj["consecutiveTimeouts"] = proxy.consecutiveTimeouts;
            proxyArray.append(obj);
        }

        QJsonDocument doc(proxyArray);

        QFile file(proxiesFilePath);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text))
        {
            file.write(doc.toJson(QJsonDocument::Indented));
            file.close();
            return true;
        }

        return false;
    }

    QList<ProxyItem> loadProxies()
    {
        QList<ProxyItem> proxies;

        QFile file(proxiesFilePath);
        if (!file.exists() || !file.open(QIODevice::ReadOnly | QIODevice::Text))
        {
            return proxies;
        }

        QByteArray data = file.readAll();
        QJsonDocument doc = QJsonDocument::fromJson(data);

        if (!doc.isArray())
        {
            return proxies;
        }

        QJsonArray proxyArray = doc.array();
        for (const QJsonValue &val : proxyArray)
        {
            QJsonObject obj = val.toObject();

            ProxyItem proxy;
            proxy.name = obj["name"].toString();
            proxy.type = obj["type"].toString();
            proxy.address = obj["address"].toString();
            proxy.port = obj["port"].toInt();
            proxy.username = obj["username"].toString();
            proxy.password = obj["password"].toString();
            proxy.uuid = obj["uuid"].toString();
            proxy.method = obj["method"].toString();
            proxy.path = obj["path"].toString();
            proxy.encryption = obj["encryption"].toString();
            proxy.tls = obj["tls"].toBool();
            proxy.isActive = obj["isActive"].toBool();
            proxy.delay = obj["delay"].toInt();
            proxy.lastTestTime = QDateTime::fromString(obj["lastTestTime"].toString(), Qt::ISODate);
            proxy.lastSuccessTime = QDateTime::fromString(obj["lastSuccessTime"].toString(), Qt::ISODate);
            proxy.consecutiveTimeouts = obj["consecutiveTimeouts"].toInt(0);

            if (!proxy.name.isEmpty() && !proxy.type.isEmpty())
            {
                proxies.append(proxy);
            }
        }

        return proxies;
    }
};

// کلاس اصلی برنامه
class MainWindow : public QMainWindow
{
    Q_OBJECT

private:
    QSpinBox *localHttpPortSpin;
    QSpinBox *localSocksPortSpin;
    QCheckBox *allowLanCheckBox;     // جایگزین redirectAllTraffic
    QCheckBox *autoStartVpnCheckBox; // چک‌باکس برای استارت خودکار
    QLabel *statusLabel, *ipLabel, *networkLabel, *currentProxyLabel;
    QLabel *localHttpLabel, *localSocksLabel, *singboxStatusLabel;
    QLabel *bestProxyPingLabel;
    QLabel *totalUploadLabel, *totalDownloadLabel; // آمار کلی
    QTextEdit *logTextEdit;

    QLineEdit *outboundUsernameEdit;
    QLineEdit *outboundPasswordEdit;

    ConfigManager *configManager;
    VpnProxyManager *vpnManager;
    AutoProxyTestManager *autoProxyTestManager;
    TrafficManager *trafficManager;

    QTimer *ipUpdateTimer;
    QTimer *autoSaveTimer;
    QTimer *updateListTimer;
    QTimer *saveFileTimer;
    QTimer *restartTimer;

    QList<ProxyItem> proxyList;
    QMap<QString, ManagedApp> managedApps;
    bool isProxyActive;
    bool isStarting;
    quint64 totalUpload, totalDownload;
    bool connectionsEstablished;
    volatile bool isShuttingDown;
    bool needsListUpdate;
    bool needsFileSave;
    bool restartScheduled;
    bool autoStartTriggered; // برای جلوگیری از استارت خودکار مکرر

    QPushButton *startVpnButton;
    QPushButton *stopVpnButton;

    QListWidget *proxyListWidget;
    QComboBox *proxyTypeCombo;
    QLineEdit *proxyNameEdit, *proxyAddressEdit, *proxyPortEdit;
    QLineEdit *proxyUserEdit, *proxyPassEdit, *proxyUuidEdit;
    QLineEdit *proxyMethodEdit, *proxyPathEdit, *proxyEncryptionEdit;
    QCheckBox *proxyTlsCheck;
    QPushButton *addProxyBtn, *removeProxyBtn, *importProxyBtn, *exportProxyBtn;

    QComboBox *logLevelCombo;
    QCheckBox *logDisabledCheck;
    QLineEdit *logOutputEdit;
    QLineEdit *dnsServerEdit;
    QSpinBox *socksPortSpin;
    QSpinBox *httpPortSpin;
    QCheckBox *autoDetectCheck;
    QCheckBox *enableSocksCheck;
    QCheckBox *enableHttpCheck;
    QListWidget *dnsServersList;
    QLineEdit *dnsServerInput;
    QPushButton *addDnsBtn, *removeDnsBtn;
    QPushButton *saveSingBoxConfigBtn, *loadSingBoxConfigBtn;

    QTableWidget *appsTable;
    QPushButton *addAppBtn, *removeAppBtn, *browseAppBtn;

    QSystemTrayIcon *trayIcon;
    QMenu *trayMenu;

public:
    MainWindow(QWidget *parent = nullptr) : QMainWindow(parent),
                                            isProxyActive(false), isStarting(false), totalUpload(0), totalDownload(0),
                                            connectionsEstablished(false), isShuttingDown(false), needsListUpdate(false), needsFileSave(false), restartScheduled(false), autoStartTriggered(false)
    {

        setWindowTitle("VPN Proxy Manager - Auto Best Proxy");
        setMinimumSize(1100, 650);

        killExistingSingBox();

        configManager = new ConfigManager(this);
        vpnManager = new VpnProxyManager(this);
        autoProxyTestManager = new AutoProxyTestManager(this);
        trafficManager = new TrafficManager(this);

        setupConnections();

        setupUI();
        loadSettings();

        ipUpdateTimer = new QTimer(this);
        connect(ipUpdateTimer, &QTimer::timeout, this, &MainWindow::updateNetworkInfo);
        ipUpdateTimer->start(60000);

        autoSaveTimer = new QTimer(this);
        connect(autoSaveTimer, &QTimer::timeout, this, &MainWindow::autoSaveConfig);
        autoSaveTimer->start(120000);

        updateListTimer = new QTimer(this);
        updateListTimer->setSingleShot(true);
        connect(updateListTimer, &QTimer::timeout, this, &MainWindow::delayedUpdateList);

        saveFileTimer = new QTimer(this);
        saveFileTimer->setSingleShot(true);
        connect(saveFileTimer, &QTimer::timeout, this, &MainWindow::delayedSaveFile);

        restartTimer = new QTimer(this);
        restartTimer->setSingleShot(true);
        connect(restartTimer, &QTimer::timeout, this, &MainWindow::onRestartTimer);

        updateNetworkInfo();

        // اگر auto-start فعال است، بعد از بارگذاری تنظیمات، VPN را شروع کن
        if (autoStartVpnCheckBox->isChecked())
        {
            QTimer::singleShot(1500, this, [this]()
                               {
                if (!autoStartTriggered && !isProxyActive && !isStarting) {
                    addLog("🔄 Auto-starting VPN...");
                    startVpn();
                    autoStartTriggered = true;
                } });
        }
    }

    void setupConnections()
    {
        if (!connectionsEstablished)
        {
            vpnManager->setupConnections();

            connect(vpnManager, &VpnProxyManager::statusChanged, this, &MainWindow::onProxyStatusChanged);
            connect(vpnManager, &VpnProxyManager::logMessage, this, &MainWindow::addLog);

            SingBoxManager *singBox = vpnManager->getSingBoxManager();
            connect(singBox, &SingBoxManager::logMessage, this, &MainWindow::addLog);
            connect(singBox, &SingBoxManager::outputReceived, this, &MainWindow::onSingBoxOutput);
            connect(singBox, &SingBoxManager::statusChanged, this, &MainWindow::onSingBoxStatusChanged);
            connect(singBox, &SingBoxManager::requestBestProxyStart, this, &MainWindow::onRequestBestProxy);

            connect(autoProxyTestManager, &AutoProxyTestManager::proxyTested, this, &MainWindow::onProxyTested);
            connect(autoProxyTestManager, &AutoProxyTestManager::testStarted, this, &MainWindow::onAutoTestStarted);
            connect(autoProxyTestManager, &AutoProxyTestManager::testFinished, this, &MainWindow::onAutoTestFinished);
            connect(autoProxyTestManager, &AutoProxyTestManager::currentProxyFailed, this, &MainWindow::onCurrentProxyFailed);

            connect(trafficManager, &TrafficManager::managedAppsUpdated, this, &MainWindow::updateManagedApps);
            connect(trafficManager, &TrafficManager::overallStatsUpdated, this, &MainWindow::updateOverallStats);

            connectionsEstablished = true;
        }
    }

    ~MainWindow()
    {
        isShuttingDown = true;

        if (autoProxyTestManager)
        {
            autoProxyTestManager->shutdown();
        }

        if (ipUpdateTimer)
            ipUpdateTimer->stop();
        if (autoSaveTimer)
            autoSaveTimer->stop();
        if (updateListTimer)
            updateListTimer->stop();
        if (saveFileTimer)
            saveFileTimer->stop();
        if (restartTimer)
            restartTimer->stop();

        if (vpnManager)
        {
            vpnManager->disconnect();
        }

        if (needsFileSave)
        {
            configManager->saveProxies(proxyList);
        }
    }

private:
    void setupUI()
    {
        QWidget *centralWidget = new QWidget(this);
        QHBoxLayout *mainLayout = new QHBoxLayout(centralWidget);

        QWidget *sidebar = createSidebar();
        mainLayout->addWidget(sidebar, 1);

        QWidget *content = createContent();
        mainLayout->addWidget(content, 3);

        setCentralWidget(centralWidget);
        createTrayIcon();
        applyModernStyle();
    }

    QWidget *createSidebar()
    {
        QWidget *sidebar = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(sidebar);

        QGroupBox *statusGroup = new QGroupBox("System Status");
        QVBoxLayout *statusLayout = new QVBoxLayout(statusGroup);

        statusLabel = new QLabel("🟡 Initializing...");
        statusLabel->setFont(QFont("Segoe UI", 9, QFont::Bold));

        singboxStatusLabel = new QLabel("🔴 Sing-Box: Stopped");
        singboxStatusLabel->setStyleSheet("color: #ff4444;");

        bestProxyPingLabel = new QLabel("📡 Best Proxy: None");
        bestProxyPingLabel->setWordWrap(true);

        currentProxyLabel = new QLabel("📡 Current: None");
        currentProxyLabel->setWordWrap(true);

        ipLabel = new QLabel("🌐 IP: Checking...");
        networkLabel = new QLabel("📡 Local: Checking...");

        // آمار کلی ترافیک
        totalUploadLabel = new QLabel("⬆️ Upload: 0 B");
        totalDownloadLabel = new QLabel("⬇️ Download: 0 B");

        statusLayout->addWidget(statusLabel);
        statusLayout->addWidget(singboxStatusLabel);
        statusLayout->addWidget(bestProxyPingLabel);
        statusLayout->addWidget(currentProxyLabel);
        statusLayout->addWidget(ipLabel);
        statusLayout->addWidget(networkLabel);
        statusLayout->addWidget(totalUploadLabel);
        statusLayout->addWidget(totalDownloadLabel);

        QGroupBox *localGroup = new QGroupBox("Local Proxy");
        QVBoxLayout *localLayout = new QVBoxLayout(localGroup);
        localHttpLabel = new QLabel("⏳ HTTP: Inactive");
        localSocksLabel = new QLabel("⏳ SOCKS5: Inactive");
        localLayout->addWidget(localHttpLabel);
        localLayout->addWidget(localSocksLabel);

        QGroupBox *vpnControlGroup = new QGroupBox("VPN Control");
        QVBoxLayout *vpnControlLayout = new QVBoxLayout(vpnControlGroup);

        startVpnButton = new QPushButton("🚀 Start VPN");
        stopVpnButton = new QPushButton("🛑 Stop VPN");
        stopVpnButton->setEnabled(false);

        startVpnButton->setStyleSheet("background-color: #28a745; color: white; font-weight: bold; padding: 8px;");
        stopVpnButton->setStyleSheet("background-color: #dc3545; color: white; font-weight: bold; padding: 8px;");

        vpnControlLayout->addWidget(startVpnButton);
        vpnControlLayout->addWidget(stopVpnButton);

        // چک‌باکس برای استارت خودکار
        autoStartVpnCheckBox = new QCheckBox("Auto-start when proxies ready");
        autoStartVpnCheckBox->setChecked(false);
        vpnControlLayout->addWidget(autoStartVpnCheckBox);

        layout->addWidget(statusGroup);
        layout->addWidget(localGroup);
        layout->addWidget(vpnControlGroup);
        layout->addStretch();

        connect(startVpnButton, &QPushButton::clicked, this, &MainWindow::startVpn);
        connect(stopVpnButton, &QPushButton::clicked, this, &MainWindow::stopVpn);

        return sidebar;
    }

    QWidget *createContent()
    {
        QWidget *content = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(content);

        QTabWidget *tabWidget = new QTabWidget;
        tabWidget->addTab(createProxyListTab(), "📋 Proxies");
        tabWidget->addTab(createAppsTab(), "📱 Apps");
        tabWidget->addTab(createSingBoxTab(), "⚙️ Settings");
        tabWidget->addTab(createLogTab(), "📝 Logs");

        layout->addWidget(tabWidget);

        return content;
    }

    QWidget *createProxyListTab()
    {
        QWidget *tab = new QWidget;
        QHBoxLayout *mainLayout = new QHBoxLayout(tab);

        QWidget *leftPanel = new QWidget;
        QVBoxLayout *leftLayout = new QVBoxLayout(leftPanel);

        QLabel *listLabel = new QLabel("📋 Proxy List (✅ Active, ❌ Timeout)");
        listLabel->setStyleSheet("font-weight: bold; color: #4a6fa5;");

        proxyListWidget = new QListWidget;
        proxyListWidget->setMinimumWidth(300);

        QHBoxLayout *listButtons = new QHBoxLayout;
        importProxyBtn = new QPushButton("📂 Import");
        exportProxyBtn = new QPushButton("💾 Export");
        listButtons->addWidget(importProxyBtn);
        listButtons->addWidget(exportProxyBtn);

        leftLayout->addWidget(listLabel);
        leftLayout->addWidget(proxyListWidget);
        leftLayout->addLayout(listButtons);

        QWidget *rightPanel = new QWidget;
        QVBoxLayout *rightLayout = new QVBoxLayout(rightPanel);

        QGroupBox *editGroup = new QGroupBox("Proxy Details");
        QGridLayout *editLayout = new QGridLayout(editGroup);

        int row = 0;
        editLayout->addWidget(new QLabel("Type:"), row, 0);
        proxyTypeCombo = new QComboBox;
        proxyTypeCombo->addItems({"http", "socks5", "shadowsocks", "vmess", "vless", "trojan"});
        editLayout->addWidget(proxyTypeCombo, row, 1, 1, 2);
        row++;

        editLayout->addWidget(new QLabel("Name:"), row, 0);
        proxyNameEdit = new QLineEdit;
        proxyNameEdit->setPlaceholderText("My Proxy");
        editLayout->addWidget(proxyNameEdit, row, 1, 1, 2);
        row++;

        editLayout->addWidget(new QLabel("Address:"), row, 0);
        proxyAddressEdit = new QLineEdit;
        proxyAddressEdit->setPlaceholderText("server.com");
        editLayout->addWidget(proxyAddressEdit, row, 1);

        editLayout->addWidget(new QLabel("Port:"), row, 2);
        proxyPortEdit = new QLineEdit;
        proxyPortEdit->setPlaceholderText("8080");
        editLayout->addWidget(proxyPortEdit, row, 3);
        row++;

        editLayout->addWidget(new QLabel("Username:"), row, 0);
        proxyUserEdit = new QLineEdit;
        proxyUserEdit->setPlaceholderText("Auth username");
        editLayout->addWidget(proxyUserEdit, row, 1, 1, 3);
        row++;

        editLayout->addWidget(new QLabel("Password:"), row, 0);
        proxyPassEdit = new QLineEdit;
        proxyPassEdit->setEchoMode(QLineEdit::Password);
        proxyPassEdit->setPlaceholderText("Auth password");
        editLayout->addWidget(proxyPassEdit, row, 1, 1, 3);
        row++;

        editLayout->addWidget(new QLabel("UUID:"), row, 0);
        proxyUuidEdit = new QLineEdit;
        proxyUuidEdit->setPlaceholderText("For VMess/VLess");
        editLayout->addWidget(proxyUuidEdit, row, 1, 1, 3);
        row++;

        editLayout->addWidget(new QLabel("Method:"), row, 0);
        proxyMethodEdit = new QLineEdit;
        proxyMethodEdit->setPlaceholderText("Encryption method");
        editLayout->addWidget(proxyMethodEdit, row, 1, 1, 3);
        row++;

        editLayout->addWidget(new QLabel("Path:"), row, 0);
        proxyPathEdit = new QLineEdit;
        proxyPathEdit->setPlaceholderText("WebSocket path");
        editLayout->addWidget(proxyPathEdit, row, 1, 1, 3);
        row++;

        editLayout->addWidget(new QLabel("Encryption:"), row, 0);
        proxyEncryptionEdit = new QLineEdit;
        proxyEncryptionEdit->setPlaceholderText("auto / none");
        editLayout->addWidget(proxyEncryptionEdit, row, 1, 1, 3);
        row++;

        proxyTlsCheck = new QCheckBox("Enable TLS");
        editLayout->addWidget(proxyTlsCheck, row, 1, 1, 3);
        row++;

        QLabel *testUrlLabel = new QLabel(
            "ℹ️ Proxies are tested only when VPN is active.\n"
            "Test URL: http://connectivitycheck.android.com/generate_204\n"
            "✅ Active: delay < 5000ms\n"
            "❌ Timeout: delay ≥ 5000ms or failed");
        testUrlLabel->setWordWrap(true);
        testUrlLabel->setStyleSheet("QLabel { background-color: #e8f4fd; padding: 8px; border-radius: 4px; color: #0c5460; margin-top: 10px; }");

        QHBoxLayout *editButtons = new QHBoxLayout;
        addProxyBtn = new QPushButton("➕ Add / Update");
        removeProxyBtn = new QPushButton("✖️ Remove");
        editButtons->addWidget(addProxyBtn);
        editButtons->addWidget(removeProxyBtn);

        rightLayout->addWidget(editGroup);
        rightLayout->addLayout(editButtons);
        rightLayout->addWidget(testUrlLabel);
        rightLayout->addStretch();

        mainLayout->addWidget(leftPanel, 1);
        mainLayout->addWidget(rightPanel, 1);

        connect(proxyListWidget, &QListWidget::itemDoubleClicked, this, &MainWindow::onProxyDoubleClicked);
        connect(addProxyBtn, &QPushButton::clicked, this, &MainWindow::addProxy);
        connect(removeProxyBtn, &QPushButton::clicked, this, &MainWindow::removeProxy);
        connect(importProxyBtn, &QPushButton::clicked, this, &MainWindow::importProxies);
        connect(exportProxyBtn, &QPushButton::clicked, this, &MainWindow::exportProxies);

        return tab;
    }

    QWidget *createSingBoxTab()
    {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);

        QGroupBox *logGroup = new QGroupBox("Log Settings");
        QGridLayout *logLayout = new QGridLayout(logGroup);

        logLayout->addWidget(new QLabel("Level:"), 0, 0);
        logLevelCombo = new QComboBox();
        logLevelCombo->addItems({"trace", "debug", "info", "warn", "error"});
        logLevelCombo->setCurrentText("info");
        logLayout->addWidget(logLevelCombo, 0, 1);

        logDisabledCheck = new QCheckBox("Disable Log");
        logLayout->addWidget(logDisabledCheck, 0, 2);

        logLayout->addWidget(new QLabel("Output:"), 1, 0);
        logOutputEdit = new QLineEdit();
        logOutputEdit->setPlaceholderText("Log file path");
        logLayout->addWidget(logOutputEdit, 1, 1, 1, 2);

        QGroupBox *dnsGroup = new QGroupBox("DNS Settings");
        QVBoxLayout *dnsLayout = new QVBoxLayout(dnsGroup);

        QHBoxLayout *dnsInputLayout = new QHBoxLayout();
        dnsServerInput = new QLineEdit();
        dnsServerInput->setPlaceholderText("8.8.8.8");
        addDnsBtn = new QPushButton("➕ Add");
        removeDnsBtn = new QPushButton("✖️ Remove");
        dnsInputLayout->addWidget(dnsServerInput);
        dnsInputLayout->addWidget(addDnsBtn);
        dnsInputLayout->addWidget(removeDnsBtn);

        dnsServersList = new QListWidget();

        dnsLayout->addLayout(dnsInputLayout);
        dnsLayout->addWidget(dnsServersList);

        QGroupBox *networkGroup = new QGroupBox("Network Settings");
        QGridLayout *networkLayout = new QGridLayout(networkGroup);

        networkLayout->addWidget(new QLabel("HTTP Port:"), 0, 0);
        httpPortSpin = new QSpinBox();
        httpPortSpin->setRange(1024, 65535);
        httpPortSpin->setValue(10809);
        networkLayout->addWidget(httpPortSpin, 0, 1);

        networkLayout->addWidget(new QLabel("SOCKS5 Port:"), 1, 0);
        socksPortSpin = new QSpinBox();
        socksPortSpin->setRange(1024, 65535);
        socksPortSpin->setValue(10808);
        networkLayout->addWidget(socksPortSpin, 1, 1);

        autoDetectCheck = new QCheckBox("Auto Detect Interface");
        autoDetectCheck->setChecked(true);
        networkLayout->addWidget(autoDetectCheck, 0, 2);

        enableSocksCheck = new QCheckBox("Enable SOCKS5");
        enableSocksCheck->setChecked(true);
        networkLayout->addWidget(enableSocksCheck, 2, 0);

        enableHttpCheck = new QCheckBox("Enable HTTP");
        enableHttpCheck->setChecked(true);
        networkLayout->addWidget(enableHttpCheck, 2, 1);

        // چک‌باکس جدید برای Allow LAN connections
        allowLanCheckBox = new QCheckBox("🌐 Allow connections from LAN");
        allowLanCheckBox->setChecked(false);
        networkLayout->addWidget(allowLanCheckBox, 2, 2);

        QGroupBox *authGroup = new QGroupBox("Client Authentication (for inbound)");
        QGridLayout *authLayout = new QGridLayout(authGroup);

        authLayout->addWidget(new QLabel("Username:"), 0, 0);
        outboundUsernameEdit = new QLineEdit();
        outboundUsernameEdit->setPlaceholderText("Username for clients");
        authLayout->addWidget(outboundUsernameEdit, 0, 1);

        authLayout->addWidget(new QLabel("Password:"), 1, 0);
        outboundPasswordEdit = new QLineEdit();
        outboundPasswordEdit->setEchoMode(QLineEdit::Password);
        outboundPasswordEdit->setPlaceholderText("Password for clients");
        authLayout->addWidget(outboundPasswordEdit, 1, 1);

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        saveSingBoxConfigBtn = new QPushButton("💾 Save Settings");
        loadSingBoxConfigBtn = new QPushButton("📂 Load Settings");
        buttonLayout->addWidget(saveSingBoxConfigBtn);
        buttonLayout->addWidget(loadSingBoxConfigBtn);
        buttonLayout->addStretch();

        QLabel *infoLabel = new QLabel(
            "ℹ️ These settings are for sing-box configuration.\n"
            "Use the VPN Control panel in the sidebar to Start/Stop the VPN.\n"
            "Client Authentication will be used for HTTP/SOCKS proxies (if provided).\n"
            "Allow LAN connections lets other devices on your network use this proxy.");
        infoLabel->setWordWrap(true);
        infoLabel->setStyleSheet("QLabel { background-color: #e8f4fd; padding: 8px; border-radius: 4px; color: #0c5460; margin-top: 10px; }");

        layout->addWidget(logGroup);
        layout->addWidget(dnsGroup);
        layout->addWidget(networkGroup);
        layout->addWidget(authGroup);
        layout->addLayout(buttonLayout);
        layout->addWidget(infoLabel);
        layout->addStretch();

        connect(addDnsBtn, &QPushButton::clicked, this, &MainWindow::addDnsServer);
        connect(removeDnsBtn, &QPushButton::clicked, this, &MainWindow::removeDnsServer);
        connect(saveSingBoxConfigBtn, &QPushButton::clicked, this, &MainWindow::saveSingBoxConfig);
        connect(loadSingBoxConfigBtn, &QPushButton::clicked, this, &MainWindow::loadSingBoxConfig);

        return tab;
    }

    QWidget *createAppsTab()
    {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        addAppBtn = new QPushButton("➕ Add App");
        removeAppBtn = new QPushButton("✖️ Remove");
        browseAppBtn = new QPushButton("📂 Browse...");
        buttonLayout->addWidget(addAppBtn);
        buttonLayout->addWidget(removeAppBtn);
        buttonLayout->addWidget(browseAppBtn);
        buttonLayout->addStretch();

        appsTable = new QTableWidget();
        appsTable->setColumnCount(7);
        appsTable->setHorizontalHeaderLabels({"Use VPN", "Force", "Application", "Path", "PID", "Upload", "Download"});
        appsTable->horizontalHeader()->setStretchLastSection(true);
        appsTable->setSelectionBehavior(QTableWidget::SelectRows);

        layout->addLayout(buttonLayout);
        layout->addWidget(appsTable);

        connect(addAppBtn, &QPushButton::clicked, this, &MainWindow::addApp);
        connect(removeAppBtn, &QPushButton::clicked, this, &MainWindow::removeApp);
        connect(browseAppBtn, &QPushButton::clicked, this, &MainWindow::browseApp);

        return tab;
    }

    QWidget *createLogTab()
    {
        QWidget *tab = new QWidget;
        QVBoxLayout *layout = new QVBoxLayout(tab);

        logTextEdit = new QTextEdit();
        logTextEdit->setReadOnly(true);
        logTextEdit->setFont(QFont("Consolas", 9));

        QHBoxLayout *buttonLayout = new QHBoxLayout();
        QPushButton *clearLogBtn = new QPushButton("🗑️ Clear");
        QPushButton *exportLogBtn = new QPushButton("💾 Export");
        buttonLayout->addWidget(clearLogBtn);
        buttonLayout->addWidget(exportLogBtn);
        buttonLayout->addStretch();

        connect(clearLogBtn, &QPushButton::clicked, this, [this]()
                { logTextEdit->clear(); });
        connect(exportLogBtn, &QPushButton::clicked, this, &MainWindow::exportLog);

        layout->addWidget(logTextEdit);
        layout->addLayout(buttonLayout);

        return tab;
    }

    void addLog(const QString &message)
    {
        if (isShuttingDown)
            return;
        QString timestamp = QDateTime::currentDateTime().toString("hh:mm:ss");
        logTextEdit->append(QString("[%1] %2").arg(timestamp).arg(message));
        QTextCursor cursor = logTextEdit->textCursor();
        cursor.movePosition(QTextCursor::End);
        logTextEdit->setTextCursor(cursor);
    }

    void loadSettings()
    {
        proxyList = configManager->loadProxies();

        SingBoxConfig config = configManager->loadSingBoxConfig();
        // به‌روزرسانی autoProxyTestManager با مقادیر پیکربندی
        autoProxyTestManager->setTestUrl(config.latencyTestUrl);
        autoProxyTestManager->setRetryInterval(config.retryInterval);

        updateProxyListWidget();
        addLog(QString("✅ Loaded %1 proxies").arg(proxyList.size()));

        QMap<QString, QVariant> appConfig = configManager->loadConfig();
        httpPortSpin->setValue(appConfig.value("local/http_port", "10809").toString().toInt());
        socksPortSpin->setValue(appConfig.value("local/socks_port", "10808").toString().toInt());
        autoStartVpnCheckBox->setChecked(appConfig.value("auto_start_vpn", false).toBool());
        addLog("✅ Configuration loaded");

        loadSingBoxConfig();

        QVariantList appsList = appConfig.value("managedApps").toList();
        for (const QVariant &appVar : appsList)
        {
            QMap<QString, QVariant> appData = appVar.toMap();
            QString name = appData.value("name").toString();
            QString path = appData.value("path").toString();
            if (!name.isEmpty())
            {
                trafficManager->addManagedApp(name, path);
            }
        }
    }

    void updateProxyListWidget()
    {
        if (isShuttingDown)
            return;

        QList<ProxyItem> tempList;
        {
            tempList = proxyList;
        }

        proxyListWidget->clear();

        std::sort(tempList.begin(), tempList.end());

        int bestDelay = -1;
        QString bestName;

        for (const ProxyItem &proxy : tempList)
        {
            QString status;
            QColor itemColor;
            QString delayText;

            if (proxy.isActive && proxy.delay > 0 && proxy.delay < 5000)
            {
                status = "✅";
                delayText = QString(" (%1 ms)").arg(proxy.delay);

                if (proxy.delay < 100)
                    itemColor = Qt::darkGreen;
                else if (proxy.delay < 200)
                    itemColor = Qt::darkYellow;
                else
                    itemColor = Qt::darkRed;

                if (bestDelay == -1 || proxy.delay < bestDelay)
                {
                    bestDelay = proxy.delay;
                    bestName = proxy.name;
                }
            }
            else
            {
                status = "❌";
                delayText = " (Timeout)";
                itemColor = Qt::gray;
            }

            QString lastSuccess = proxy.lastSuccessTime.isValid() ? QString(" Last: %1").arg(proxy.lastSuccessTime.toString("hh:mm")) : "";

            QString text = QString("%1 %2 - %3 (%4:%5)%6%7")
                               .arg(status)
                               .arg(proxy.name)
                               .arg(proxy.type)
                               .arg(proxy.address)
                               .arg(proxy.port)
                               .arg(delayText)
                               .arg(lastSuccess);

            QListWidgetItem *item = new QListWidgetItem(text);
            item->setForeground(itemColor);
            // ذخیره نام پروکسی در داده آیتم برای حذف آسان
            item->setData(Qt::UserRole, proxy.name);

            if (proxy.isActive && proxy.delay > 0 && proxy.delay == bestDelay)
            {
                QFont font = item->font();
                font.setBold(true);
                item->setFont(font);
            }

            proxyListWidget->addItem(item);
        }

        if (bestProxyPingLabel)
        {
            if (bestDelay > 0)
            {
                bestProxyPingLabel->setText(QString("📡 Best: %1 (%2 ms)").arg(bestName).arg(bestDelay));
            }
            else
            {
                bestProxyPingLabel->setText("📡 Best: No active proxy");
            }
        }
    }

    void requestListUpdate()
    {
        if (isShuttingDown)
            return;
        needsListUpdate = true;
        if (!updateListTimer->isActive())
        {
            updateListTimer->start(500);
        }
    }

    void delayedUpdateList()
    {
        if (isShuttingDown)
            return;
        if (needsListUpdate)
        {
            needsListUpdate = false;
            updateProxyListWidget();
        }
    }

    void requestFileSave()
    {
        if (isShuttingDown)
            return;
        needsFileSave = true;
        if (!saveFileTimer->isActive())
        {
            saveFileTimer->start(2000);
        }
    }

    void delayedSaveFile()
    {
        if (isShuttingDown)
            return;
        if (needsFileSave)
        {
            needsFileSave = false;
            configManager->saveProxies(proxyList);
        }
    }

    void scheduleRestart()
    {
        if (isShuttingDown || restartScheduled)
            return;
        restartScheduled = true;
        restartTimer->start(2000);
    }

    void onRestartTimer()
    {
        if (isShuttingDown)
            return;
        restartScheduled = false;

        if (!isProxyActive)
            return;

        SingBoxManager *singBox = vpnManager->getSingBoxManager();
        if (!singBox)
            return;

        ProxyItem current = singBox->getCurrentProxy();

        QList<ProxyItem> activeProxies;
        for (const ProxyItem &p : proxyList)
        {
            if (p.isActive && p.delay > 0 && p.delay < 5000)
            {
                activeProxies.append(p);
            }
        }

        if (activeProxies.isEmpty())
        {
            if (isProxyActive)
            {
                vpnManager->disconnect();
                addLog("⚠️ No active proxies, stopping VPN");
            }
            return;
        }

        ProxyItem best = activeProxies.first();
        int bestDelay = best.delay;
        for (const ProxyItem &p : activeProxies)
        {
            if (p.delay < bestDelay)
            {
                bestDelay = p.delay;
                best = p;
            }
        }

        if (best.name != current.name)
        {
            addLog(QString("🔄 Switching to better proxy: %1 (%2 ms)").arg(best.name).arg(best.delay));
            singBox->restartWithBestProxy();
        }
        else if (!current.isActive)
        {
            addLog("🔄 Current proxy failed, restarting with best available");
            singBox->restartWithBestProxy();
        }
    }

    void updateManagedApps(const QMap<QString, ManagedApp> &apps)
    {
        if (isShuttingDown)
            return;
        managedApps = apps;
        appsTable->setRowCount(managedApps.size());

        int row = 0;
        for (const ManagedApp &app : managedApps)
        {
            QCheckBox *useProxyCheck = new QCheckBox();
            useProxyCheck->setChecked(app.useProxy);
            connect(useProxyCheck, &QCheckBox::toggled, [this, app](bool checked)
                    {
                if (!isShuttingDown) {
                    trafficManager->setManagedAppUseProxy(app.name, checked);
                } });

            QCheckBox *forceProxyCheck = new QCheckBox();
            forceProxyCheck->setChecked(app.forceProxy);
            connect(forceProxyCheck, &QCheckBox::toggled, [this, app](bool checked)
                    {
                if (!isShuttingDown) {
                    trafficManager->setManagedAppForceProxy(app.name, checked);
                } });

            QWidget *useProxyWidget = new QWidget();
            QHBoxLayout *useProxyLayout = new QHBoxLayout(useProxyWidget);
            useProxyLayout->addWidget(useProxyCheck);
            useProxyLayout->setAlignment(Qt::AlignCenter);
            useProxyLayout->setContentsMargins(0, 0, 0, 0);

            QWidget *forceProxyWidget = new QWidget();
            QHBoxLayout *forceProxyLayout = new QHBoxLayout(forceProxyWidget);
            forceProxyLayout->addWidget(forceProxyCheck);
            forceProxyLayout->setAlignment(Qt::AlignCenter);
            forceProxyLayout->setContentsMargins(0, 0, 0, 0);

            appsTable->setCellWidget(row, 0, useProxyWidget);
            appsTable->setCellWidget(row, 1, forceProxyWidget);
            appsTable->setItem(row, 2, new QTableWidgetItem(app.name));
            appsTable->setItem(row, 3, new QTableWidgetItem(app.path));
            appsTable->setItem(row, 4, new QTableWidgetItem(app.pid ? QString::number(app.pid) : "-"));

            // نمایش ترافیک
            QString upStr = formatBytes(app.totalUpload);
            QString downStr = formatBytes(app.totalDownload);
            appsTable->setItem(row, 5, new QTableWidgetItem(upStr));
            appsTable->setItem(row, 6, new QTableWidgetItem(downStr));

            row++;
        }
    }

    void updateOverallStats(quint64 up, quint64 down)
    {
        totalUpload = up;
        totalDownload = down;
        totalUploadLabel->setText("⬆️ Upload: " + formatBytes(up));
        totalDownloadLabel->setText("⬇️ Download: " + formatBytes(down));
    }

    QString formatBytes(quint64 bytes)
    {
        const char *suffixes[] = {"B", "KB", "MB", "GB", "TB"};
        int i = 0;
        double d = bytes;
        while (d >= 1024 && i < 4)
        {
            d /= 1024;
            i++;
        }
        return QString::number(d, 'f', 1) + " " + suffixes[i];
    }

    void updateStatus()
    {
        if (isShuttingDown)
            return;
        if (isProxyActive)
        {
            statusLabel->setText("🟢 VPN Active");
            statusLabel->setStyleSheet("color: #00aa00; font-weight: bold;");
            startVpnButton->setEnabled(false);
            stopVpnButton->setEnabled(true);
        }
        else
        {
            statusLabel->setText("🟡 VPN Inactive");
            statusLabel->setStyleSheet("color: #856404; font-weight: bold;");
            startVpnButton->setEnabled(true);
            stopVpnButton->setEnabled(false);
        }

        updateLocalPortsInfo();
    }

    void updateLocalPortsInfo()
    {
        if (isShuttingDown)
            return;
        if (isProxyActive)
        {
            SingBoxManager *singBox = vpnManager->getSingBoxManager();
            bool allowLan = singBox ? singBox->getConfig().allowLan : false;
            QString httpAddr = allowLan ? "0.0.0.0" : "127.0.0.1";
            QString socksAddr = allowLan ? "0.0.0.0" : "127.0.0.1";
            localHttpLabel->setText(QString("✅ HTTP: %1:%2 (Active)").arg(httpAddr).arg(vpnManager->getLocalHttpPort()));
            localHttpLabel->setStyleSheet("color: #155724; font-weight: bold;");
            localSocksLabel->setText(QString("✅ SOCKS5: %1:%2 (Active)").arg(socksAddr).arg(vpnManager->getLocalSocksPort()));
            localSocksLabel->setStyleSheet("color: #155724; font-weight: bold;");
        }
        else
        {
            localHttpLabel->setText("⏳ HTTP: Inactive");
            localHttpLabel->setStyleSheet("color: #856404; font-weight: bold;");
            localSocksLabel->setText("⏳ SOCKS5: Inactive");
            localSocksLabel->setStyleSheet("color: #856404; font-weight: bold;");
        }
    }

    void startAutoProxyTesting()
    {
        // این تابع دیگر مستقیماً فراخوانی نمی‌شود، بلکه از طریق setActive کنترل می‌شود
        // اما برای سازگاری نگه داشته شده
        if (!isShuttingDown && !proxyList.isEmpty())
        {
            autoProxyTestManager->setActive(true);
        }
    }

    void createTrayIcon()
    {
        trayIcon = new QSystemTrayIcon(this);
        trayIcon->setIcon(QApplication::style()->standardIcon(QStyle::SP_ComputerIcon));
        trayIcon->setToolTip("VPN Proxy Manager");

        trayMenu = new QMenu(this);
        QAction *showAction = new QAction("Show", this);
        QAction *quitAction = new QAction("Quit", this);

        connect(showAction, &QAction::triggered, this, &QWidget::show);
        connect(quitAction, &QAction::triggered, qApp, &QApplication::quit);

        trayMenu->addAction(showAction);
        trayMenu->addAction(quitAction);
        trayIcon->setContextMenu(trayMenu);
        trayIcon->show();

        connect(trayIcon, &QSystemTrayIcon::activated, [this](QSystemTrayIcon::ActivationReason reason)
                {
            if (!isShuttingDown && reason == QSystemTrayIcon::DoubleClick) show(); });
    }

    void applyModernStyle()
    {
        setStyleSheet(R"(
            QMainWindow { background: #f5f5f5; }
            QGroupBox {
                border: 2px solid #ccc;
                border-radius: 6px;
                margin-top: 8px;
                padding-top: 10px;
                background: white;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                subcontrol-position: top center;
                padding: 0 8px;
                background: white;
            }
            QPushButton {
                background: #4a6fa5;
                color: white;
                border: none;
                padding: 6px 12px;
                border-radius: 4px;
            }
            QPushButton:hover { background: #3a5a85; }
            QPushButton:pressed { background: #2a4a75; }
            QTableWidget, QLineEdit, QTextEdit, QListWidget {
                background: white;
                border: 1px solid #ccc;
                border-radius: 3px;
                padding: 3px;
            }
            QTabBar::tab {
                background: #6c757d;
                color: white;
                padding: 6px 12px;
                margin: 2px;
                border-radius: 4px;
            }
            QTabBar::tab:selected { background: #4a6fa5; }
            QHeaderView::section {
                background: #e8e8e8;
                padding: 6px;
                border: 1px solid #ccc;
            }
        )");
    }

    void loadProxies()
    {
        proxyList = configManager->loadProxies();
        requestListUpdate();
    }

    void saveProxies()
    {
        if (!isShuttingDown)
        {
            requestFileSave();
        }
    }

private slots:
    void onProxyStatusChanged(bool connected)
    {
        if (isShuttingDown)
            return;
        isProxyActive = connected;
        isStarting = false;
        updateStatus();
        requestListUpdate();
        updateNetworkInfo();

        // اطلاع به TrafficManager برای شبیه‌سازی ترافیک
        trafficManager->setVpnActive(connected);

        // وقتی VPN فعال می‌شود، پروکسی جاری را به تست‌کننده اطلاع بده
        if (connected)
        {
            ProxyItem current = vpnManager->getCurrentProxyItem();
            if (!current.name.isEmpty())
            {
                autoProxyTestManager->setCurrentProxy(current.name);
            }
        }
        else
        {
            autoProxyTestManager->setCurrentProxy("");
            // وقتی VPN متوقف می‌شود، تست‌ها را غیرفعال کن
            autoProxyTestManager->setActive(false);
        }
    }

    void onSingBoxStatusChanged(bool running)
    {
        if (isShuttingDown)
            return;
        singboxStatusLabel->setText(running ? "🟢 Sing-Box: Running" : "🔴 Sing-Box: Stopped");
        singboxStatusLabel->setStyleSheet(running ? "color: #00aa00;" : "color: #ff4444;");

        if (running)
        {
            ProxyItem current = vpnManager->getSingBoxManager()->getCurrentProxy();
            if (current.name.isEmpty())
            {
                currentProxyLabel->setText("📡 Current: None");
            }
            else
            {
                currentProxyLabel->setText(QString("📡 Current: %1 (%2 ms)").arg(current.name).arg(current.delay));
                // به‌روزرسانی پروکسی جاری در تست‌کننده
                autoProxyTestManager->setCurrentProxy(current.name);
            }
        }
        else
        {
            currentProxyLabel->setText("📡 Current: None");
            autoProxyTestManager->setCurrentProxy("");
        }
    }

    void onSingBoxOutput(const QString &output)
    {
        if (isShuttingDown)
            return;
        if (output.contains("FATAL") || output.contains("ERROR"))
        {
            addLog("[Error] " + output);
        }
    }

    void onProxyTested(const QString &name, int delay)
    {
        if (isShuttingDown)
            return;

        bool changed = false;
        QString currentProxyName = vpnManager->getCurrentProxyItem().name;

        for (int i = 0; i < proxyList.size(); i++)
        {
            if (proxyList[i].name == name)
            {
                bool newActive = (delay >= 0 && delay < 5000);

                if (!newActive)
                {
                    proxyList[i].consecutiveTimeouts++;
                }
                else
                {
                    proxyList[i].consecutiveTimeouts = 0;
                }

                if (proxyList[i].isActive != newActive || proxyList[i].delay != delay)
                {
                    proxyList[i].isActive = newActive;
                    proxyList[i].delay = delay;
                    proxyList[i].lastTestTime = QDateTime::currentDateTime();
                    if (delay >= 0 && delay < 5000)
                    {
                        proxyList[i].lastSuccessTime = QDateTime::currentDateTime();
                    }
                    changed = true;
                }
                break;
            }
        }

        if (changed)
        {
            requestListUpdate();
            saveProxies();
        }

        if (delay >= 0 && delay < 5000)
        {
            addLog(QString("✅ %1: %2 ms").arg(name).arg(delay));
        }
        else
        {
            addLog(QString("❌ %1 timeout or failed").arg(name));
        }
    }

    void onAutoTestStarted(int total)
    {
        if (isShuttingDown)
            return;
        addLog(QString("🔄 Testing %1 proxies...").arg(total));
    }

    void onAutoTestFinished()
    {
        if (isShuttingDown)
            return;
        addLog("✅ Testing completed");

        bool hasActive = false;
        for (const ProxyItem &p : proxyList)
        {
            if (p.isActive && p.delay > 0 && p.delay < 5000)
            {
                hasActive = true;
                break;
            }
        }

        // اگر VPN فعال است و پروکسی فعالی وجود دارد، بررسی کن که آیا نیاز به سوئیچ است
        if (isProxyActive && hasActive)
        {
            scheduleRestart();
        }
    }

    // اسلات برای شکست پروکسی جاری
    void onCurrentProxyFailed()
    {
        if (isShuttingDown)
            return;
        if (!isProxyActive)
            return; // اگر VPN فعال نیست، کاری نکن

        SingBoxManager *singBox = vpnManager->getSingBoxManager();
        if (!singBox)
            return;

        // اگر sing-box در حال تغییر وضعیت است، restart نکن
        if (singBox->isBusy())
        {
            addLog("⚠️ Sing-Box is busy, will retry later");
            return;
        }

        addLog("⚠️ Current proxy failed, switching immediately...");

        // پیدا کردن بهترین پروکسی فعال
        QList<ProxyItem> activeProxies;
        for (const ProxyItem &p : proxyList)
        {
            if (p.isActive && p.delay > 0 && p.delay < 5000)
            {
                activeProxies.append(p);
            }
        }

        if (activeProxies.isEmpty())
        {
            addLog("❌ No active proxies available, stopping VPN");
            vpnManager->disconnect();
            return;
        }

        // انتخاب بهترین (کمترین تاخیر)
        ProxyItem best = activeProxies.first();
        int bestDelay = best.delay;
        for (const ProxyItem &p : activeProxies)
        {
            if (p.delay < bestDelay)
            {
                bestDelay = p.delay;
                best = p;
            }
        }

        // راه‌اندازی مجدد با پروکسی جدید
        if (singBox)
        {
            addLog(QString("🔄 Switching to %1 (%2 ms)").arg(best.name).arg(best.delay));
            singBox->restartWithBestProxy();
        }
    }

    void updateNetworkInfo()
    {
        if (isShuttingDown)
            return;
        QString localIp = "No connection";
        for (const QHostAddress &addr : QNetworkInterface::allAddresses())
        {
            if (addr.protocol() == QAbstractSocket::IPv4Protocol && addr != QHostAddress::LocalHost)
            {
                localIp = addr.toString();
                break;
            }
        }
        networkLabel->setText("📡 Local: " + localIp);

        checkPublicIp();
    }

    void checkPublicIp()
    {
        if (isShuttingDown)
            return;
        QNetworkAccessManager *manager = new QNetworkAccessManager(this);

        if (isProxyActive)
        {
            QNetworkProxy proxy;
            proxy.setType(QNetworkProxy::HttpProxy);
            proxy.setHostName("127.0.0.1");
            proxy.setPort(vpnManager->getLocalHttpPort());
            manager->setProxy(proxy);
        }

        QNetworkRequest request(QUrl("https://api.ipify.org?format=json"));
        request.setHeader(QNetworkRequest::UserAgentHeader, "VPN-Proxy-Manager/9.5");

        QNetworkReply *reply = manager->get(request);
        connect(reply, &QNetworkReply::finished, [=]()
                {
            if (isShuttingDown) {
                reply->deleteLater();
                manager->deleteLater();
                return;
            }
            if (reply->error() == QNetworkReply::NoError) {
                QJsonObject obj = QJsonDocument::fromJson(reply->readAll()).object();
                QString ip = obj["ip"].toString();
                ipLabel->setText("🌐 IP: " + ip);
                ipLabel->setStyleSheet(isProxyActive ? "color: #00aa00;" : "color: #666;");
            }
            reply->deleteLater();
            manager->deleteLater(); });
    }

    void onRequestBestProxy()
    {
        if (isShuttingDown)
            return;

        static bool isProcessing = false;
        if (isProcessing)
        {
            addLog("⚠️ Start request ignored - already processing");
            return;
        }

        if (isStarting || isProxyActive)
        {
            addLog("⚠️ Already starting or connected");
            return;
        }

        isProcessing = true;
        isStarting = true;

        // فعال کردن تست‌ها قبل از استارت
        autoProxyTestManager->setActive(true);

        bool hasActive = false;
        for (const ProxyItem &p : proxyList)
        {
            if (p.isActive && p.delay > 0 && p.delay < 5000)
            {
                hasActive = true;
                break;
            }
        }

        if (hasActive)
        {
            addLog("🚀 Starting with best proxy...");
            SingBoxConfig config = configManager->loadSingBoxConfig();
            vpnManager->getSingBoxManager()->setConfig(config);

            bool result = vpnManager->startWithBestProxy(proxyList, httpPortSpin->value(), socksPortSpin->value());
            if (!result)
            {
                isStarting = false;
                // اگر استارت نشد، تست‌ها را غیرفعال کن
                autoProxyTestManager->setActive(false);
            }
        }
        else
        {
            addLog("⏳ No active proxies yet, waiting for test results...");
            // تست‌ها فعال هستند و به زودی نتیجه می‌دهند
            isStarting = false; // ریست می‌کنیم تا بعداً توسط onAutoTestFinished استارت شود
        }

        isProcessing = false;
    }

    void startVpn()
    {
        onRequestBestProxy();
    }

    void stopVpn()
    {
        if (isShuttingDown)
            return;
        // قبل از توقف، پروکسی جاری را غیرفعال کن تا از restartهای اضافی جلوگیری شود
        autoProxyTestManager->setCurrentProxy("");
        vpnManager->disconnect();
        isStarting = false;
        // تست‌ها در onProxyStatusChanged غیرفعال می‌شوند
    }

    void addDnsServer()
    {
        if (isShuttingDown)
            return;
        QString server = dnsServerInput->text().trimmed();
        if (!server.isEmpty())
        {
            bool exists = false;
            for (int i = 0; i < dnsServersList->count(); i++)
            {
                if (dnsServersList->item(i)->text() == server)
                {
                    exists = true;
                    break;
                }
            }
            if (!exists)
            {
                dnsServersList->addItem(server);
                dnsServerInput->clear();
            }
        }
    }

    void removeDnsServer()
    {
        if (isShuttingDown)
            return;
        int row = dnsServersList->currentRow();
        if (row >= 0)
            delete dnsServersList->takeItem(row);
    }

    void saveSingBoxConfig()
    {
        if (isShuttingDown)
            return;
        SingBoxConfig config;
        config.logLevel = logLevelCombo->currentText();
        config.logDisabled = logDisabledCheck->isChecked();
        config.logOutput = logOutputEdit->text();
        config.socksPort = socksPortSpin->value();
        config.httpPort = httpPortSpin->value();
        config.autoDetectInterface = autoDetectCheck->isChecked();
        config.enableSocks = enableSocksCheck->isChecked();
        config.enableHttp = enableHttpCheck->isChecked();
        config.allowLan = allowLanCheckBox->isChecked();
        config.outboundUsername = outboundUsernameEdit->text();
        config.outboundPassword = outboundPasswordEdit->text();
        // دریافت مقادیر تست از autoProxyTestManager (که از فایل لود شده یا پیش‌فرض است)
        config.latencyTestUrl = autoProxyTestManager->getTestUrl();
        config.retryInterval = autoProxyTestManager->getRetryInterval();

        config.dnsServers.clear();
        for (int i = 0; i < dnsServersList->count(); i++)
        {
            QString server = dnsServersList->item(i)->text();
            if (!config.dnsServers.contains(server))
            {
                config.dnsServers.append(server);
            }
        }

        if (configManager->saveSingBoxConfig(config))
        {
            vpnManager->getSingBoxManager()->setConfig(config);
            // autoProxyTestManager قبلاً با این مقادیر تنظیم شده، اما برای اطمینان دوباره set می‌کنیم
            autoProxyTestManager->setTestUrl(config.latencyTestUrl);
            autoProxyTestManager->setRetryInterval(config.retryInterval);
            addLog("✅ Settings saved");
        }
    }

    void loadSingBoxConfig()
    {
        if (isShuttingDown)
            return;
        SingBoxConfig config = configManager->loadSingBoxConfig();

        logLevelCombo->setCurrentText(config.logLevel);
        logDisabledCheck->setChecked(config.logDisabled);
        logOutputEdit->setText(config.logOutput);
        socksPortSpin->setValue(config.socksPort);
        httpPortSpin->setValue(config.httpPort);
        autoDetectCheck->setChecked(config.autoDetectInterface);
        enableSocksCheck->setChecked(config.enableSocks);
        enableHttpCheck->setChecked(config.enableHttp);
        allowLanCheckBox->setChecked(config.allowLan);
        outboundUsernameEdit->setText(config.outboundUsername);
        outboundPasswordEdit->setText(config.outboundPassword);

        dnsServersList->clear();
        QStringList uniqueServers;
        for (const QString &server : config.dnsServers)
        {
            if (!uniqueServers.contains(server))
            {
                uniqueServers.append(server);
                dnsServersList->addItem(server);
            }
        }

        vpnManager->getSingBoxManager()->setConfig(config);
        // به‌روزرسانی autoProxyTestManager با مقادیر پیکربندی
        autoProxyTestManager->setTestUrl(config.latencyTestUrl);
        autoProxyTestManager->setRetryInterval(config.retryInterval);
    }

    void addProxy()
    {
        if (isShuttingDown)
            return;
        ProxyItem proxy;
        proxy.name = proxyNameEdit->text();
        proxy.type = proxyTypeCombo->currentText();
        proxy.address = proxyAddressEdit->text();
        proxy.port = proxyPortEdit->text().toInt();
        proxy.username = proxyUserEdit->text();
        proxy.password = proxyPassEdit->text();
        proxy.uuid = proxyUuidEdit->text();
        proxy.method = proxyMethodEdit->text();
        proxy.path = proxyPathEdit->text();
        proxy.encryption = proxyEncryptionEdit->text();
        proxy.tls = proxyTlsCheck->isChecked();
        proxy.isActive = false;
        proxy.delay = -1;
        proxy.lastTestTime = QDateTime::currentDateTime();
        proxy.consecutiveTimeouts = 0;

        if (proxy.name.isEmpty() || proxy.address.isEmpty() || proxy.port <= 0)
        {
            addLog("⚠️ Fill required fields");
            return;
        }

        bool updated = false;
        for (int i = 0; i < proxyList.size(); i++)
        {
            if (proxyList[i].name == proxy.name)
            {
                proxyList[i] = proxy;
                updated = true;
                addLog(QString("✅ Updated '%1'").arg(proxy.name));
                break;
            }
        }

        if (!updated)
        {
            proxyList.append(proxy);
            addLog(QString("✅ Added '%1'").arg(proxy.name));
        }

        saveProxies();
        requestListUpdate();

        autoProxyTestManager->setProxyList(proxyList);
        // اگر VPN فعال است، پروکسی جدید را تست کن
        if (isProxyActive)
        {
            autoProxyTestManager->testProxy(proxy.name);
        }

        proxyNameEdit->clear();
        proxyAddressEdit->clear();
        proxyPortEdit->clear();
        proxyUserEdit->clear();
        proxyPassEdit->clear();
        proxyUuidEdit->clear();
        proxyMethodEdit->clear();
        proxyPathEdit->clear();
        proxyEncryptionEdit->clear();
        proxyTlsCheck->setChecked(false);
    }

    void removeProxy()
    {
        if (isShuttingDown)
            return;
        int row = proxyListWidget->currentRow();
        if (row >= 0)
        {
            QListWidgetItem *item = proxyListWidget->item(row);
            if (!item)
                return;

            QString name = item->data(Qt::UserRole).toString();
            if (name.isEmpty())
            {
                // Fallback: استخراج از متن
                QString text = item->text();
                // حذف ایموجی و فاصله
                if (text.startsWith("✅") || text.startsWith("❌"))
                {
                    int dashIndex = text.indexOf(" - ");
                    if (dashIndex > 2)
                    {
                        name = text.mid(2, dashIndex - 2).trimmed();
                    }
                    else
                    {
                        // اگر خط تیره نبود، اولین کلمه بعد از ایموجی
                        QStringList parts = text.mid(2).split(" ");
                        if (!parts.isEmpty())
                            name = parts.first();
                    }
                }
            }

            if (name.isEmpty())
            {
                addLog("⚠️ Could not identify proxy to remove");
                return;
            }

            // حذف با تطبیق دقیق نام (case-sensitive)
            bool removed = false;
            for (int i = 0; i < proxyList.size(); i++)
            {
                if (proxyList[i].name == name)
                {
                    proxyList.removeAt(i);
                    removed = true;
                    addLog(QString("✅ Removed '%1'").arg(name));
                    break;
                }
            }

            // اگر پیدا نشد، با تطبیق case-insensitive و trim
            if (!removed)
            {
                QString nameTrimmed = name.trimmed();
                for (int i = 0; i < proxyList.size(); i++)
                {
                    if (proxyList[i].name.trimmed().compare(nameTrimmed, Qt::CaseInsensitive) == 0)
                    {
                        proxyList.removeAt(i);
                        removed = true;
                        addLog(QString("✅ Removed '%1' (case-insensitive)").arg(name));
                        break;
                    }
                }
            }

            if (removed)
            {
                saveProxies();
                requestListUpdate();
                autoProxyTestManager->setProxyList(proxyList);

                if (isProxyActive && vpnManager->getCurrentProxyItem().name == name)
                {
                    // اگر پروکسی جاری حذف شد، فوراً سوئیچ کن
                    onCurrentProxyFailed();
                }
            }
            else
            {
                addLog(QString("⚠️ Proxy '%1' not found in list").arg(name));
            }
        }
        else
        {
            addLog("⚠️ No proxy selected");
        }
    }

    void onProxyDoubleClicked(QListWidgetItem *item)
    {
        if (isShuttingDown)
            return;
        QString name = item->data(Qt::UserRole).toString();
        if (name.isEmpty())
        {
            // fallback
            QString text = item->text();
            if (text.startsWith("✅") || text.startsWith("❌"))
            {
                int dashIndex = text.indexOf(" - ");
                if (dashIndex > 2)
                {
                    name = text.mid(2, dashIndex - 2).trimmed();
                }
            }
        }

        for (const ProxyItem &proxy : proxyList)
        {
            if (proxy.name == name)
            {
                proxyTypeCombo->setCurrentText(proxy.type);
                proxyNameEdit->setText(proxy.name);
                proxyAddressEdit->setText(proxy.address);
                proxyPortEdit->setText(QString::number(proxy.port));
                proxyUserEdit->setText(proxy.username);
                proxyPassEdit->setText(proxy.password);
                proxyUuidEdit->setText(proxy.uuid);
                proxyMethodEdit->setText(proxy.method);
                proxyPathEdit->setText(proxy.path);
                proxyEncryptionEdit->setText(proxy.encryption);
                proxyTlsCheck->setChecked(proxy.tls);
                break;
            }
        }
    }

    void importProxies()
    {
        if (isShuttingDown)
            return;
        QString file = QFileDialog::getOpenFileName(this, "Import Proxies",
                                                    QDir::homePath(), "JSON (*.json)");

        if (!file.isEmpty())
        {
            QFile f(file);
            if (f.open(QIODevice::ReadOnly))
            {
                QJsonArray array = QJsonDocument::fromJson(f.readAll()).array();
                int count = 0;

                for (const QJsonValue &val : array)
                {
                    QJsonObject obj = val.toObject();

                    ProxyItem proxy;
                    proxy.name = obj["name"].toString();
                    proxy.type = obj["type"].toString();
                    proxy.address = obj["address"].toString();
                    proxy.port = obj["port"].toInt();
                    proxy.username = obj["username"].toString();
                    proxy.password = obj["password"].toString();
                    proxy.uuid = obj["uuid"].toString();
                    proxy.method = obj["method"].toString();
                    proxy.path = obj["path"].toString();
                    proxy.encryption = obj["encryption"].toString();
                    proxy.tls = obj["tls"].toBool();
                    proxy.isActive = false;
                    proxy.delay = -1;
                    proxy.lastTestTime = QDateTime::currentDateTime();
                    proxy.consecutiveTimeouts = 0;

                    if (!proxy.name.isEmpty())
                    {
                        proxyList.append(proxy);
                        count++;
                    }
                }

                f.close();
                addLog(QString("✅ Imported %1 proxies").arg(count));
                saveProxies();
                requestListUpdate();
                autoProxyTestManager->setProxyList(proxyList);
                // اگر VPN فعال است، تست‌ها را شروع کن
                if (isProxyActive)
                {
                    autoProxyTestManager->setActive(true);
                }
            }
        }
    }

    void exportProxies()
    {
        if (isShuttingDown)
            return;
        QString file = QFileDialog::getSaveFileName(this, "Export Proxies",
                                                    QDir::homePath() + "/proxies.json", "JSON (*.json)");

        if (!file.isEmpty())
        {
            configManager->saveProxies(proxyList);
            QFile::copy(configManager->getProxiesFilePath(), file);
            addLog(QString("✅ Exported %1 proxies").arg(proxyList.size()));
        }
    }

    void addApp()
    {
        if (isShuttingDown)
            return;
        QString name = QInputDialog::getText(this, "Add App", "App name:");
        if (!name.isEmpty())
        {
            trafficManager->addManagedApp(name, "");
            addLog(QString("✅ Added app: %1").arg(name));
        }
    }

    void removeApp()
    {
        if (isShuttingDown)
            return;
        int row = appsTable->currentRow();
        if (row >= 0)
        {
            QString name = appsTable->item(row, 2)->text();
            trafficManager->removeManagedApp(name);
            addLog(QString("✅ Removed app: %1").arg(name));
        }
    }

    void browseApp()
    {
        if (isShuttingDown)
            return;
        QString path = QFileDialog::getOpenFileName(this, "Select App",
                                                    QDir::homePath(), "EXE (*.exe)");

        if (!path.isEmpty())
        {
            QFileInfo info(path);
            trafficManager->addManagedApp(info.baseName(), path);
            addLog(QString("✅ Added app: %1").arg(info.baseName()));
        }
    }

    void exportLog()
    {
        if (isShuttingDown)
            return;
        QString file = QDateTime::currentDateTime().toString("'log_'yyyyMMdd_HHmmss'.txt'");
        QFile f(file);
        if (f.open(QIODevice::WriteOnly))
        {
            f.write(logTextEdit->toPlainText().toUtf8());
            f.close();
            addLog("✅ Log saved to: " + file);
        }
    }

    void autoSaveConfig()
    {
        if (isShuttingDown)
            return;
        QMap<QString, QVariant> config;
        config["local/http_port"] = QString::number(httpPortSpin->value());
        config["local/socks_port"] = QString::number(socksPortSpin->value());
        config["auto_start_vpn"] = autoStartVpnCheckBox->isChecked();

        QVariantList appsList;
        for (const ManagedApp &app : managedApps)
        {
            QMap<QString, QVariant> appData;
            appData["name"] = app.name;
            appData["path"] = app.path;
            appsList.append(appData);
        }
        config["managedApps"] = appsList;

        configManager->saveConfig(config);
        saveProxies();
        saveSingBoxConfig();
    }

protected:
    void closeEvent(QCloseEvent *event) override
    {
        isShuttingDown = true;

        if (autoProxyTestManager)
        {
            autoProxyTestManager->shutdown();
        }
        if (ipUpdateTimer)
            ipUpdateTimer->stop();
        if (autoSaveTimer)
            autoSaveTimer->stop();
        if (updateListTimer)
            updateListTimer->stop();
        if (saveFileTimer)
            saveFileTimer->stop();
        if (restartTimer)
            restartTimer->stop();

        if (needsFileSave)
        {
            configManager->saveProxies(proxyList);
        }

        autoSaveConfig();

        if (trayIcon->isVisible())
        {
            hide();
            event->ignore();
        }
        else
        {
            event->accept();
        }
    }
};

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QSharedMemory sharedMemory("VPNProxyManagerInstance");
    if (!sharedMemory.create(1))
    {
        QMessageBox::warning(nullptr, "Warning", "Application is already running!");
        return 1;
    }

    killExistingSingBox();

    app.setApplicationName("VPN Proxy Manager");
    app.setApplicationVersion("9.5");
    app.setQuitOnLastWindowClosed(false);

    MainWindow window;
    window.show();

    return app.exec();
}

#include "main.moc"