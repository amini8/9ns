#include "ui/ConfigSession.h"

#include <system_error>
#include <utility>

namespace {

// Backup kept next to config.json before a recovery import overwrites it.
const char* kBackupSuffix = ".replaced.bak";

}  // namespace

ConfigSession::ConfigSession(std::filesystem::path configPath, QObject* parent, ExistsProbe existsProbe)
    : QObject(parent), configPath_(std::move(configPath)), existsProbe_(std::move(existsProbe)) {
    if (!existsProbe_) {
        existsProbe_ = [](const std::filesystem::path& path, std::error_code& ec) {
            return std::filesystem::exists(path, ec);
        };
    }
    QString error;
    if (!reload(error)) {
        // state_/loadError_ already record the problem; the caller decides how
        // to surface it. A genuinely absent file is not an error.
    }
}

void ConfigSession::setDraft(Config config) {
    draft_ = std::move(config);
    dirty_ = true;
    emit changed();
}

void ConfigSession::mutateDraft(const std::function<void(Config&)>& mutate) {
    mutate(draft_);
    dirty_ = true;
    emit changed();
}

void ConfigSession::markDirty() {
    dirty_ = true;
    emit changed();
}

void ConfigSession::setState(State state, QString loadError) {
    state_ = state;
    loadError_ = std::move(loadError);
}

bool ConfigSession::save(QString& error) {
    error.clear();
    if (state_ == State::Failed) {
        error = tr("The configuration file could not be loaded (%1). "
                   "Repair the file or import a replacement before saving.")
                    .arg(loadError_);
        return false;
    }
    try {
        // saveConfig validates and writes through a temporary file.
        saveConfig(configPath_, draft_);
    } catch (const std::exception& e) {
        error = QString::fromUtf8(e.what());
        return false;
    }
    saved_ = draft_;
    dirty_ = false;
    setState(State::Loaded, QString());
    emit changed();
    return true;
}

bool ConfigSession::reload(QString& error) {
    error.clear();
    std::error_code ec;
    const bool exists = existsProbe_(configPath_, ec);
    if (ec) {
        error = tr("Cannot inspect configuration '%1': %2")
                    .arg(QString::fromStdWString(configPath_.wstring()), QString::fromStdString(ec.message()));
        setState(State::Failed, error);
        emit changed();
        return false;
    }

    if (!exists) {
        // A genuinely absent file is a clean slate, not a failure.
        const Config defaults = defaultConfig();
        draft_ = defaults;
        saved_ = defaults;
        dirty_ = false;
        setState(State::Missing, QString());
        emit changed();
        return true;
    }

    try {
        Config loaded = loadConfig(configPath_);
        draft_ = loaded;
        saved_ = loaded;
        dirty_ = false;
        setState(State::Loaded, QString());
        emit changed();
        return true;
    } catch (const std::exception& e) {
        error = QString::fromUtf8(e.what());
        setState(State::Failed, error);
        emit changed();
        return false;
    }
}

bool ConfigSession::replaceFromFile(const std::filesystem::path& source, QString& error) {
    error.clear();
    Config candidate;
    try {
        candidate = loadConfig(source);
    } catch (const std::exception& e) {
        error = tr("The imported file is not a usable configuration: %1").arg(QString::fromUtf8(e.what()));
        return false;
    }

    // Preserve whatever is currently on disk before overwriting it.
    std::error_code ec;
    const bool exists = existsProbe_(configPath_, ec);
    if (ec) {
        error = tr("Cannot inspect existing configuration '%1' (%2); the import was aborted.")
                    .arg(QString::fromStdWString(configPath_.wstring()), QString::fromStdString(ec.message()));
        return false;
    }
    if (exists) {
        std::filesystem::path backup = configPath_;
        backup += kBackupSuffix;
        std::filesystem::copy_file(configPath_, backup,
                                   std::filesystem::copy_options::overwrite_existing, ec);
        if (ec) {
            error = tr("Cannot back up the existing configuration (%1); the import was aborted.")
                        .arg(QString::fromStdString(ec.message()));
            return false;
        }
    }

    try {
        saveConfig(configPath_, candidate);
    } catch (const std::exception& e) {
        error = tr("Cannot write the imported configuration: %1").arg(QString::fromUtf8(e.what()));
        return false;
    }

    draft_ = candidate;
    saved_ = candidate;
    dirty_ = false;
    setState(State::Loaded, QString());
    emit changed();
    return true;
}
