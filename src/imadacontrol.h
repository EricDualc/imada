// Copyright (c) 2015-2017 The Bitcoin Core developers
// Copyright (c) 2017 The IMADA developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

/**
 * Functionality for communicating with ImadaGate.
 */
#ifndef BITCOIN_IMADACONTROL_H
#define BITCOIN_IMADACONTROL_H

#include <string>

#include <boost/function.hpp>
#include <boost/chrono/chrono.hpp>
#include <boost/thread.hpp>

extern const std::string DEFAULT_IMADA_CONTROL;
static const bool DEFAULT_LISTEN_ONION = true;

void StartImadaControl(boost::thread_group& threadGroup);
void InterruptImadaControl();
void StopImadaControl();

#endif /* BITCOIN_IMADACONTROL_H */


