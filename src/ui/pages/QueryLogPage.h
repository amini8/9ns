#pragma once

#include <QWidget>

#include "core/Resolver.h"

class QAbstractItemModel;
class QComboBox;
class QLabel;
class QLineEdit;
class QPushButton;
class QSortFilterProxyModel;
class QStackedLayout;
class QTableView;

// Live query log: labeled domain search, status filter, stable-time rows and
// selected-query inspection. Display only — MainWindow owns the model and the
// Engine, and handles persistence.
class QueryLogPage : public QWidget {
    Q_OBJECT

public:
    explicit QueryLogPage(QWidget* parent = nullptr);

    // The model must outlive the page. `proxy` is the filtering/sorting proxy
    // the page drives; MainWindow routes inspection through it.
    void setModels(QAbstractItemModel* source, QSortFilterProxyModel* proxy);
    void focusSearch();

    // Row currently selected in the view, or -1.
    int selectedSourceRow() const;

signals:
    void searchChanged(const QString& pattern);
    void statusFilterChanged(const QString& status);
    void inspectRequested(const ResolveEvent& event);
    void blockDomainRequested(const QString& domain);
    void bypassDomainRequested(const QString& domain);
    void clearRequested();

private:
    void showNoResults(bool noResults);
    void updateEmptyState();
    void inspectIndex(const QModelIndex& index);

    QLineEdit* searchEdit_ = nullptr;
    QComboBox* statusFilter_ = nullptr;
    QTableView* tableView_ = nullptr;
    QLabel* emptyLabel_ = nullptr;
    QPushButton* clearButton_ = nullptr;
    QStackedLayout* contentStack_ = nullptr;
    QAbstractItemModel* source_ = nullptr;
    QSortFilterProxyModel* proxy_ = nullptr;
};
