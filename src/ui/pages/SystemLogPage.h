#pragma once

#include <QWidget>

class QPlainTextEdit;

// Append-only system diagnostics log with explicit clear and open-folder
// actions. Display only: lines arrive from MainWindow's logger sink.
class SystemLogPage : public QWidget {
    Q_OBJECT

public:
    explicit SystemLogPage(QWidget* parent = nullptr);

public slots:
    void appendLine(const QString& line);
    void clear();

signals:
    void openDataFolderRequested();

private:
    QPlainTextEdit* logView_ = nullptr;
};
