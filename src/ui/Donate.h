#pragma once

class QWidget;

namespace Donate {

// Native SegWit (bech32) Bitcoin address.
inline constexpr char kBtcAddress[] = "bc1qe0fg8qsc6n7ffke22qz38727e0nxnersq0en2u";

void showDialog(QWidget* parent);

}  
