#pragma once

#include <filesystem>
#include <functional>
#include <string>
#include <system_error>

#include <QObject>
#include <QString>

#include "core/Config.h"

// GUI-owned working state for the configuration file: the editable draft, the
// last successfully persisted state, the load-error guard and dirty tracking.
//
// Use it from the UI thread only. It does not own the Engine and never starts or
// stops it; MainWindow keeps the started runtime configuration separately.
class ConfigSession : public QObject {
    Q_OBJECT

public:
    // Missing: no file on disk yet. Loaded: a valid file was read. Failed: the
    // file cannot be inspected/loaded, is invalid or uses removed features.
    enum class State { Missing, Loaded, Failed };

    // Optional metadata probe keeps filesystem-error regressions deterministic.
    // The default uses std::filesystem::exists without throwing.
    using ExistsProbe = std::function<bool(const std::filesystem::path&, std::error_code&)>;
    explicit ConfigSession(std::filesystem::path configPath, QObject* parent = nullptr,
                           ExistsProbe existsProbe = {});
    ~ConfigSession() override = default;

    ConfigSession(const ConfigSession&) = delete;
    ConfigSession& operator=(const ConfigSession&) = delete;

    State state() const { return state_; }
    // Human-readable load failure. Empty unless state() == Failed.
    QString loadError() const { return loadError_; }

    // The editable working copy. Never write it back to disk without save().
    // The non-const overload is for dialogs that edit the draft in place; the
    // caller must then go through setDraft()/mutateDraft() so dirty tracking
    // stays honest.
    Config& draft() { return draft_; }
    const Config& draft() const { return draft_; }
    // Replaces the draft wholesale and marks the session dirty.
    void setDraft(Config config);
    // Applies an edit to the draft and marks the session dirty.
    void mutateDraft(const std::function<void(Config&)>& mutate);
    // Marks the draft dirty after a dialog mutated it in place. Use when the
    // editor holds a reference to draft() rather than going through mutateDraft.
    void markDirty();

    // The values last successfully written to disk.
    const Config& saved() const { return saved_; }
    bool isDirty() const { return dirty_; }

    // True while a load failure is being held off: writes, engine start and the
    // setup wizard must be refused until the file is repaired or replaced.
    bool writesBlocked() const { return state_ == State::Failed; }

    // Validates and writes the draft atomically. On success commits saved_ to the
    // draft and clears dirty. On failure the draft and saved state are unchanged.
    bool save(QString& error);

    // Re-reads the file. On success replaces draft and saved and clears dirty.
    // On failure keeps the current draft untouched and records the load error.
    bool reload(QString& error);

    // Explicit recovery path for a failed load: validates the given replacement
    // file, backs up whatever is currently on disk, then persists the candidate.
    // The caller must confirm the replacement before invoking this. On failure
    // nothing on disk or in memory changes.
    bool replaceFromFile(const std::filesystem::path& source, QString& error);

signals:
    // Emitted whenever state, load error, draft, saved values or dirty changed.
    void changed();

private:
    void setState(State state, QString loadError);

    std::filesystem::path configPath_;
    ExistsProbe existsProbe_;
    State state_ = State::Missing;
    QString loadError_;
    Config draft_;
    Config saved_;
    bool dirty_ = false;
};
