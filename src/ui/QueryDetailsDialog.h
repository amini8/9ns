#pragma once

#include <QDialog>

#include "core/Resolver.h"

class QPlainTextEdit;
class QTreeWidget;

// Dialog inspecting raw and parsed DNS packet sections (Header, Question, Answer, Authority, Additional, Hex Dump).
class QueryDetailsDialog : public QDialog {
    Q_OBJECT

public:
    explicit QueryDetailsDialog(const ResolveEvent& event, QWidget* parent = nullptr);
    ~QueryDetailsDialog() override = default;

private:
    void populate(const ResolveEvent& event);
    static QString formatHexDump(const dns::Bytes& data);

    QTreeWidget* treeWidget_ = nullptr;
    QPlainTextEdit* hexView_ = nullptr;
};
