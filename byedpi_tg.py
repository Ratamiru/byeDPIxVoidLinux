#!/usr/bin/env python3
"""
ByeDPI × TG Desktop — маленький GUI для Linux (Void и др.).

Запускает два локальных прокси:
  • byedpi (ciadpi)  — SOCKS5 для браузера и Discord, обход DPI
  • tg-ws-proxy      — MTProto-прокси для Telegram Desktop через WebSocket

Сам ничего не проксирует — только управляет процессами. Логика проверок и подбора в dpi_core.py.
"""
from __future__ import annotations

import os
import secrets
import shlex
import shutil
import signal
import subprocess
import sys

from PySide6.QtCore import QProcess, QThread, Qt, Signal, QTimer
from PySide6.QtGui import (QAction, QColor, QFont, QGuiApplication, QIcon,
                           QPainter, QPalette, QPixmap)
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox,
                               QComboBox, QFrame, QGridLayout, QHBoxLayout,
                               QHeaderView, QInputDialog, QLabel, QLineEdit, QMainWindow,
                               QMenu, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QSpinBox, QSystemTrayIcon,
                               QTableWidget, QTableWidgetItem, QTabWidget,
                               QVBoxLayout, QWidget)

import dpi_core as core
from dpi_core import (CFG_DIR, CFG_FILE, CIADPI, REPORT_FILE, STRATEGIES_URL, TGWS_DIR,
                      USER_STRATEGIES, VENV_PY, REASONS, SERVICE_TITLES, VPN_WARNING,
                      Row, load_cfg, load_strategies, port_busy, rank, save_cfg)

APP_NAME = "ByeDPI × TG"

# ─────────────────────────── виджеты ───────────────────────────

def dot_pixmap(color: str, size: int = 12) -> QPixmap:
    pm = QPixmap(size, size)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setBrush(QColor(color))
    p.setPen(Qt.NoPen)
    p.drawEllipse(0, 0, size, size)
    p.end()
    return pm


def tray_icon(sites_on: bool, tg_on: bool) -> QIcon:
    """Иконка трея: левая половина — сайты, правая — Telegram."""
    s = 64
    pm = QPixmap(s, s)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    p.setPen(Qt.NoPen)
    p.setBrush(QColor("#3ddc84" if sites_on else "#555b66"))
    p.drawPie(4, 4, s - 8, s - 8, 90 * 16, 180 * 16)
    p.setBrush(QColor("#2aa3e6" if tg_on else "#3c414a"))
    p.drawPie(4, 4, s - 8, s - 8, 270 * 16, 180 * 16)
    p.end()
    return QIcon(pm)


class Card(QFrame):
    def __init__(self, title: str):
        super().__init__()
        self.setObjectName("card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(16, 14, 16, 14)
        self.lay.setSpacing(10)
        head = QHBoxLayout()
        self.dot = QLabel()
        self.dot.setPixmap(dot_pixmap("#555b66"))
        t = QLabel(title)
        t.setObjectName("cardTitle")
        self.status = QLabel("Остановлен")
        self.status.setObjectName("status")
        self.toggle = QPushButton("Запустить")
        self.toggle.setObjectName("toggle")
        self.toggle.setCheckable(True)
        self.toggle.setMinimumWidth(110)
        head.addWidget(self.dot)
        head.addWidget(t)
        head.addSpacing(8)
        head.addWidget(self.status, 1)
        head.addWidget(self.toggle)
        self.lay.addLayout(head)

    def set_state(self, state: str, text: str | None = None):
        colors = {"on": "#3ddc84", "off": "#555b66", "err": "#ef5350", "wait": "#ffb74d"}
        labels = {"on": "Работает", "off": "Остановлен", "err": "Ошибка", "wait": "Запуск…"}
        self.dot.setPixmap(dot_pixmap(colors[state]))
        self.status.setText(text or labels[state])
        self.toggle.blockSignals(True)
        self.toggle.setChecked(state in ("on", "wait"))
        self.toggle.setText("Остановить" if state in ("on", "wait") else "Запустить")
        self.toggle.blockSignals(False)


class StrategyTester(QThread):
    progress = Signal(int, int, str)      # i, total, args
    row = Signal(object)                  # core.Row
    done = Signal(object, object, bool)   # все строки, лучшая, остановлен?
    failed = Signal(str)

    def __init__(self, strategies: list[str], cfg: dict, sni: str, own_args: str):
        super().__init__()
        self.strategies, self.cfg, self.sni, self.own_args = strategies, cfg, sni, own_args
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        cfg = self.cfg
        ipv4 = bool(cfg.get("ipv4_only", True))
        rows, best = [], None
        try:
            node = core.discover_video_node()
            if not node and self.own_args:
                with core.running_ciadpi(self.own_args, self.sni, ipv4) as port:
                    node = core.discover_video_node(port) if port else None
            rows, best = core.pick_strategies(
                self.strategies, core.all_targets(cfg, node), self.sni,
                float(cfg.get("probe_timeout", 8)), ipv4, cfg.get("probe_fingerprint", "firefox"),
                on_progress=self.progress.emit, on_row=self.row.emit,
                should_stop=lambda: self._stop)
        except (OSError, ValueError) as e:
            self.failed.emit(f"Не удалось запустить ciadpi: {e}")
        self.done.emit(rows, best, self._stop)


class ScoreItem(QTableWidgetItem):
    """Ячейка «5/6», которая сортируется как число."""

    def __init__(self, ok: int, total: int):
        super().__init__(f"{ok}/{total}")
        self.value = ok / total if total else 0
        self.setTextAlignment(Qt.AlignCenter)
        self.setForeground(QColor("#3ddc84" if ok == total else ("#ffb74d" if ok else "#ef5350")))

    def __lt__(self, other):
        return self.value < other.value


class Worker(QThread):
    """Запустить функцию в фоне и вернуть результат сигналом."""
    finished_with = Signal(object)

    def __init__(self, fn):
        super().__init__()
        self.fn = fn

    def run(self):
        self.finished_with.emit(self.fn())


# ─────────────────────────── главное окно ───────────────────────────

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.cfg = load_cfg()
        self.quitting = False
        self.tester: StrategyTester | None = None
        self._workers: list[QThread] = []
        self._user_stopped: set[int] = set()
        self.setWindowTitle(APP_NAME)
        self.setMinimumSize(620, 980)
        self.tun_on = False

        self.p_dpi = QProcess(self)
        self.p_tg = QProcess(self)
        for proc, name in ((self.p_dpi, "dpi"), (self.p_tg, "tg")):
            proc.setProcessChannelMode(QProcess.MergedChannels)
            proc.readyReadStandardOutput.connect(lambda p=proc, n=name: self._read(p, n))
            proc.started.connect(lambda n=name: self._started(n))
            proc.finished.connect(lambda code, st, n=name: self._finished(n, code, st))
            proc.errorOccurred.connect(lambda err, n=name: self._error(n, err))

        central = QWidget()
        root = QVBoxLayout(central)
        root.setContentsMargins(16, 16, 16, 16)
        root.setSpacing(12)
        self.setCentralWidget(central)

        self.vpn_label = QLabel()
        self.vpn_label.setObjectName("warn")
        self.vpn_label.setWordWrap(True)
        self.vpn_label.hide()
        root.addWidget(self.vpn_label)
        self._refresh_vpn()
        self._vpn_timer = QTimer(self)
        self._vpn_timer.timeout.connect(self._refresh_vpn)
        self._vpn_timer.start(5000)

        root.addWidget(self._build_dpi_card())
        root.addWidget(self._build_tun_card())
        root.addWidget(self._build_voice_card())
        root.addWidget(self._build_tg_card())

        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_test_tab(), "Подбор стратегий")
        self.log_dpi = self._log_view()
        self.log_tg = self._log_view()
        self.tabs.addTab(self.log_dpi, "Лог byedpi")
        self.tabs.addTab(self.log_tg, "Лог Telegram")
        root.addWidget(self.tabs, 1)

        opts = QHBoxLayout()
        self.cb_auto_dpi = QCheckBox("Автозапуск сайтов")
        self.cb_auto_tg = QCheckBox("Автозапуск Telegram")
        self.cb_hidden = QCheckBox("Стартовать в трее")
        self.cb_auto_dpi.setChecked(self.cfg["autostart_byedpi"])
        self.cb_auto_tg.setChecked(self.cfg["autostart_tg"])
        self.cb_hidden.setChecked(self.cfg["start_hidden"])
        for cb in (self.cb_auto_dpi, self.cb_auto_tg, self.cb_hidden):
            cb.toggled.connect(self._save_opts)
            opts.addWidget(cb)
        opts.addStretch()
        root.addLayout(opts)

        self._build_tray()
        self._check_install()

        if self.cfg["autostart_byedpi"]:
            QTimer.singleShot(200, self.start_dpi)
        if self.cfg["autostart_tg"]:
            QTimer.singleShot(300, self.start_tg)

    # ---------- построение UI ----------

    def _log_view(self) -> QPlainTextEdit:
        v = QPlainTextEdit()
        v.setReadOnly(True)
        v.setMaximumBlockCount(3000)
        v.setFont(QFont("monospace", 9))
        return v

    def _build_dpi_card(self) -> Card:
        c = Card("Сайты · byedpi")
        self.card_dpi = c
        c.toggle.toggled.connect(lambda on: self.start_dpi() if on else self.stop_dpi())

        g = QGridLayout()
        g.setHorizontalSpacing(8)
        g.addWidget(QLabel("Стратегия"), 0, 0)
        self.preset = QComboBox()
        self.preset.setSizeAdjustPolicy(QComboBox.AdjustToMinimumContentsLengthWithIcon)
        self.preset.setMinimumContentsLength(20)
        g.addWidget(self.preset, 0, 1, 1, 3)

        g.addWidget(QLabel("Аргументы"), 1, 0)
        self.dpi_args = QLineEdit(self.cfg["byedpi_args"])
        self.dpi_args.setCursorPosition(0)
        self.dpi_args.setFont(QFont("monospace", 9))
        self.dpi_args.setPlaceholderText("-o1 -d1 -a1 … ({sni} заменится на Fake SNI)")
        g.addWidget(self.dpi_args, 1, 1, 1, 3)

        g.addWidget(QLabel("Порт SOCKS5"), 2, 0)
        self.dpi_port = QSpinBox()
        self.dpi_port.setRange(1024, 65535)
        self.dpi_port.setValue(self.cfg["byedpi_port"])
        g.addWidget(self.dpi_port, 2, 1)
        g.addWidget(QLabel("Fake SNI"), 2, 2, Qt.AlignRight)
        self.fake_sni = QLineEdit(self.cfg["fake_sni"])
        self.fake_sni.setToolTip("Подставляется вместо {sni} в стратегиях с -n (поддельный ClientHello)")
        g.addWidget(self.fake_sni, 2, 3)
        g.setColumnStretch(1, 1)
        g.setColumnStretch(3, 1)
        c.lay.addLayout(g)

        self._fill_presets()
        self.preset.activated.connect(self._preset_chosen)

        row = QHBoxLayout()
        self.btn_check = QPushButton("Проверить сервисы")
        self.btn_check.setToolTip("Проверить YouTube и Discord через запущенный прокси")
        self.btn_check.clicked.connect(self.check_now)
        self.btn_dns = QPushButton("Проверить DNS")
        self.btn_dns.clicked.connect(self.check_dns)
        btn_copy = QPushButton("Копировать адрес")
        btn_copy.clicked.connect(lambda: self._copy(self._socks_url(), "Адрес SOCKS скопирован"))
        for b in (self.btn_check, self.btn_dns, btn_copy):
            row.addWidget(b)
        row.addStretch()
        c.lay.addLayout(row)

        row2 = QHBoxLayout()
        btn_browser = QPushButton("Браузер")
        btn_browser.setToolTip(
            "Открывает браузер с готовыми настройками прокси в отдельном профиле.\n"
            "Основной профиль не меняется, и браузер можно не закрывать.")
        btn_browser.clicked.connect(lambda: self.launch_browser())
        btn_discord = QPushButton("Discord")
        btn_discord.setToolTip(
            "Запускает клиент Discord через прокси, а если его нет, открывает сайт в браузере.\n"
            "Текст, картинки и вход работают через прокси. Голос идёт по UDP мимо него: для него есть карточка ниже.")
        btn_discord.clicked.connect(self.launch_discord)
        btn_pac = QPushButton("PAC для своего браузера")
        btn_pac.setToolTip(
            "Создаёт файл автонастройки: через прокси идут только YouTube и Discord,\n"
            "а если прокси выключен, браузер работает напрямую.")
        btn_pac.clicked.connect(self.setup_pac)
        for b in (btn_browser, btn_discord, btn_pac):
            row2.addWidget(b)
        row2.addStretch()
        c.lay.addLayout(row2)
        return c

    def _build_tun_card(self) -> Card:
        c = Card("Все приложения · TUN")
        self.card_tun = c
        self.tun_busy = False
        c.toggle.toggled.connect(lambda on: self._tun_action("start" if on else "stop"))
        hint = QLabel("Весь TCP системы идёт через byedpi: клиент Discord, лаунчеры, любые программы "
                      "без настройки прокси. Стратегия и порт берутся из карточки «Сайты». "
                      "Telegram, локальная сеть и UDP идут мимо.")
        hint.setObjectName("hint")
        hint.setWordWrap(True)
        c.lay.addWidget(hint)
        self.cb_quic = QCheckBox("Отклонять QUIC (UDP/443): браузер сразу пойдёт по TCP через byedpi")
        self.cb_quic.setChecked(not self.cfg.get("tun_allow_quic", False))
        self.cb_quic.toggled.connect(self._tun_quic_chosen)
        c.lay.addWidget(self.cb_quic)
        self._refresh_tun()
        return c

    def _build_voice_card(self) -> Card:
        c = Card("Голос Discord · nfqws")
        self.card_voice = c
        self.voice_busy = False
        c.toggle.toggled.connect(self.toggle_voice)
        row = QHBoxLayout()
        row.addWidget(QLabel("Профиль"))
        self.voice_profile = QComboBox()
        self.voice_profile.setToolTip(
            "Голос нельзя проверить автоматически: зайди в голосовой канал.\n"
            "Если зависает на «Подключение к RTC», выбери следующий профиль.")
        for key, title in core.VOICE_PROFILES.items():
            self.voice_profile.addItem(title, key)
        idx = self.voice_profile.findData(self.cfg.get("voice_profile"))
        self.voice_profile.setCurrentIndex(max(idx, 0))
        self.voice_profile.activated.connect(self._voice_profile_chosen)
        row.addWidget(self.voice_profile, 1)
        c.lay.addLayout(row)
        self._refresh_voice()
        return c

    def _build_tg_card(self) -> Card:
        c = Card("Telegram · tg-ws-proxy")
        self.card_tg = c
        c.toggle.toggled.connect(lambda on: self.start_tg() if on else self.stop_tg())

        g = QGridLayout()
        g.setHorizontalSpacing(8)
        g.addWidget(QLabel("Порт"), 0, 0)
        self.tg_port = QSpinBox()
        self.tg_port.setRange(1024, 65535)
        self.tg_port.setValue(self.cfg["tg_port"])
        g.addWidget(self.tg_port, 0, 1)
        g.addWidget(QLabel("Secret"), 0, 2)
        self.tg_secret = QLineEdit(self.cfg["tg_secret"])
        self.tg_secret.setMaxLength(32)
        self.tg_secret.setFont(QFont("monospace", 9))
        g.addWidget(self.tg_secret, 0, 3)
        btn_regen = QPushButton("↻")
        btn_regen.setToolTip("Сгенерировать новый secret")
        btn_regen.setFixedWidth(34)
        btn_regen.clicked.connect(lambda: self.tg_secret.setText(secrets.token_hex(16)))
        g.addWidget(btn_regen, 0, 4)
        g.addWidget(QLabel("Доп. флаги"), 1, 0)
        self.tg_extra = QLineEdit(self.cfg["tg_extra_args"])
        self.tg_extra.setPlaceholderText("напр. --dc-ip 4:149.154.167.220  или  --no-cfproxy")
        g.addWidget(self.tg_extra, 1, 1, 1, 4)
        g.setColumnStretch(3, 1)
        c.lay.addLayout(g)

        row = QHBoxLayout()
        btn_open = QPushButton("Применить в Telegram")
        btn_open.setObjectName("accent")
        btn_open.clicked.connect(self.open_in_telegram)
        btn_link = QPushButton("Копировать ссылку")
        btn_link.clicked.connect(lambda: self._copy(self._tg_link("https://t.me/proxy"),
                                                    "Ссылка на прокси скопирована"))
        row.addWidget(btn_open)
        row.addWidget(btn_link)
        row.addStretch()
        c.lay.addLayout(row)
        return c

    def _build_test_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(8, 8, 8, 8)

        top = QHBoxLayout()
        self.btn_test = QPushButton("Подобрать стратегию")
        self.btn_test.setObjectName("accent")
        self.btn_test.clicked.connect(self.run_tester)
        self.btn_apply = QPushButton("Применить выбранную")
        self.btn_apply.clicked.connect(self._apply_selected)
        self.btn_update = QPushButton("Обновить список")
        self.btn_update.setToolTip("Скачать свежий список стратегий из ByeByeDPI (romanvht) на GitHub")
        self.btn_update.clicked.connect(self.update_strategies)
        self.btn_report = QPushButton("Отчёт")
        self.btn_report.setToolTip("Собрать диагностику сети в файл. Запускай с выключенным VPN.")
        self.btn_report.clicked.connect(self.make_report)
        top.addWidget(self.btn_test)
        top.addWidget(self.btn_apply)
        top.addStretch()
        top.addWidget(self.btn_report)
        top.addWidget(self.btn_update)
        lay.addLayout(top)

        self.test_info = QLabel()
        self.test_info.setObjectName("hint")
        self.test_info.setWordWrap(True)
        lay.addWidget(self.test_info)
        self.test_bar = QProgressBar()
        self.test_bar.setTextVisible(True)
        self.test_bar.hide()
        lay.addWidget(self.test_bar)

        self.table = QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["YouTube", "Discord", "Стратегия"])
        for col in (0, 1):
            self.table.horizontalHeader().setSectionResizeMode(col, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.verticalHeader().hide()
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFont(QFont("monospace", 9))
        self.table.setSortingEnabled(True)
        self.table.doubleClicked.connect(lambda _: self._apply_selected())
        lay.addWidget(self.table, 1)
        self._update_test_info()
        return w

    def _build_tray(self):
        self.tray = None
        if not QSystemTrayIcon.isSystemTrayAvailable():
            return
        self.tray = QSystemTrayIcon(tray_icon(False, False), self)
        self.tray.setToolTip(APP_NAME)
        m = QMenu()
        self.act_dpi = QAction("Сайты", m, checkable=True)
        self.act_tg = QAction("Telegram", m, checkable=True)
        self.act_dpi.triggered.connect(lambda on: self.start_dpi() if on else self.stop_dpi())
        self.act_tg.triggered.connect(lambda on: self.start_tg() if on else self.stop_tg())
        m.addAction(self.act_dpi)
        m.addAction(self.act_tg)
        m.addSeparator()
        m.addAction("Применить в Telegram", self.open_in_telegram)
        m.addAction("Показать окно", self._show)
        m.addSeparator()
        m.addAction("Выход", self.quit_app)
        self.tray.setContextMenu(m)
        self.tray.activated.connect(
            lambda r: self._toggle_window() if r == QSystemTrayIcon.Trigger else None)
        self.tray.show()

    # ---------- helpers ----------

    def _check_install(self):
        missing = []
        if not CIADPI.exists():
            missing.append(f"byedpi: {CIADPI}")
        if not (TGWS_DIR / "proxy" / "tg_ws_proxy.py").exists():
            missing.append(f"tg-ws-proxy: {TGWS_DIR}")
        if not shutil.which("curl"):
            missing.append("curl (нужен для проверок)")
        if core.cffi_requests is None:
            self._log("dpi", "Нет curl_cffi: проверки идут с отпечатком curl и менее точны. "
                             "Запусти install.sh, чтобы его поставить.")
        if missing:
            QMessageBox.warning(self, APP_NAME,
                                "Не найдено:\n\n" + "\n".join(missing) +
                                "\n\nЗапусти install.sh из папки проекта.")

    def _python(self) -> str:
        return str(VENV_PY) if VENV_PY.exists() else sys.executable

    def _socks_url(self) -> str:
        return f"socks5://127.0.0.1:{self.dpi_port.value()}"

    def _tg_link(self, base: str = "tg://proxy") -> str:
        return (f"{base}?server=127.0.0.1&port={self.tg_port.value()}"
                f"&secret=dd{self.tg_secret.text().strip()}")

    def _copy(self, text: str, msg: str):
        QGuiApplication.clipboard().setText(text)
        self.statusBar().showMessage(msg, 3000)

    def _refresh_vpn(self):
        dev, is_vpn = core.route_info()
        self.vpn_dev = dev if is_vpn else None
        if is_vpn:
            self.vpn_label.setText("⚠ " + VPN_WARNING.format(dev=dev))
        self.vpn_label.setVisible(is_vpn)
        if hasattr(self, "card_voice"):
            self._refresh_voice()
        if hasattr(self, "card_tun"):
            self._refresh_tun()

    def _refresh_tun(self):
        if self.tun_busy:
            return
        c = self.card_tun
        if not core.TUN_HELPER.exists():
            c.set_state("off", "Не установлен: ./install.sh tun")
            c.toggle.setEnabled(False)
            self.cb_quic.setEnabled(False)
            return
        c.toggle.setEnabled(True)
        self.cb_quic.setEnabled(True)
        st = core.tun_status()
        was_on, self.tun_on = self.tun_on, st.running
        if st.running:
            c.set_state("on", f"Работает · {st.dev} → 127.0.0.1:{st.port}"
                              + (" · VPN: не действует" if self.vpn_dev else ""))
            c.status.setToolTip("QUIC " + ("отклоняется" if st.quic == "block" else "пропускается")
                                + (", IPv6 тоже через туннель" if st.ipv6 else "")
                                + (f"\nТрафик сейчас идёт через {self.vpn_dev}, туннель на него не влияет."
                                   if self.vpn_dev else ""))
            if self.p_dpi.state() == QProcess.NotRunning:
                self.card_dpi.set_state("on", f"Работает в режиме TUN · 127.0.0.1:{st.port}")
        else:
            c.set_state("off")
            if was_on and self.p_dpi.state() == QProcess.NotRunning:
                self.card_dpi.set_state("off")
        self.card_dpi.toggle.setEnabled(not st.running)
        if hasattr(self, "tray"):
            self._refresh_tray()

    def _tun_quic_chosen(self, block: bool):
        self.cfg["tun_allow_quic"] = not block
        save_cfg(self.cfg)
        if core.tun_status().running:
            self._tun_action("start")

    def _tun_action(self, action: str, password: str | None = None):
        port, args = None, None
        if action == "start":
            if self.tester and self.tester.isRunning():
                self.card_tun.set_state("off", "Сначала дождись конца подбора")
                return
            self._save()
            try:
                args = core.tun_argv(self.dpi_args.text(), self.fake_sni.text().strip(),
                                     bool(self.cfg.get("ipv4_only", True)))
            except ValueError as e:
                self.card_tun.set_state("err", f"Аргументы: {e}")
                return
            port = self.dpi_port.value()
            # ciadpi режима TUN займёт тот же порт: браузер и Discord, настроенные на SOCKS, продолжат работать
            self._dpi_before_tun = self.p_dpi.state() != QProcess.NotRunning
            self.stop_dpi()
        allow_quic = bool(self.cfg.get("tun_allow_quic", False))
        self.tun_busy = True
        self.card_tun.set_state("wait", "Запуск…" if action == "start" else "Остановка…")
        self.card_tun.toggle.setEnabled(False)
        self._bg(lambda: core.tun_run(action, port, args, allow_quic, password),
                 lambda res, a=action: self._tun_done(a, res))

    def _tun_done(self, action: str, res):
        code, text = res if isinstance(res, tuple) else (1, str(res))
        self.tun_busy = False
        self.card_tun.toggle.setEnabled(True)
        if code == core.NEED_PASSWORD:
            pw, ok = QInputDialog.getText(self, "Режим TUN",
                                          "Пароль sudo. Нужен, чтобы поднять туннель и правила маршрутизации:",
                                          QLineEdit.Password)
            if ok and pw:
                self._tun_action(action, pw)
                return
        elif code != 0:
            QMessageBox.warning(self, "Режим TUN", text or "Хелпер завершился с ошибкой.")
        elif text:
            self._log("dpi", text)
        self._refresh_tun()
        if action == "start" and not self.tun_on and getattr(self, "_dpi_before_tun", False):
            self.start_dpi()      # туннель не поднялся — возвращаем обычный SOCKS

    def _refresh_voice(self):
        if self.voice_busy:
            return
        c = self.card_voice
        if not core.VOICE_HELPER.exists():
            c.set_state("off", "Не установлен: ./install.sh voice")
            c.toggle.setEnabled(False)
            self.voice_profile.setEnabled(False)
            return
        c.toggle.setEnabled(True)
        self.voice_profile.setEnabled(True)
        st = core.voice_status()
        if not st.running:
            c.set_state("off")
            return
        c.set_state("on", "Работает · VPN: не действует" if self.vpn_dev else f"Работает · {st.iface}, {st.profile}")
        c.status.setToolTip(f"Интерфейс {st.iface}, профиль {st.profile}."
                            + (f"\nЗвук сейчас идёт через {self.vpn_dev}, режим на него не влияет." if self.vpn_dev else ""))

    def toggle_voice(self, on: bool):
        self._voice_action("start" if on else "stop")

    def _voice_profile_chosen(self):
        self.cfg["voice_profile"] = self.voice_profile.currentData()
        save_cfg(self.cfg)
        if core.voice_status().running:
            self._voice_action("start")

    def _voice_action(self, action: str, password: str | None = None):
        profile = self.voice_profile.currentData() if action == "start" else None
        self.voice_busy = True
        self.card_voice.set_state("wait", "Запуск…" if action == "start" else "Остановка…")
        self.card_voice.toggle.setEnabled(False)
        self._bg(lambda: core.voice_run(action, profile, password),
                 lambda res, a=action: self._voice_done(a, res))

    def _voice_done(self, action: str, res):
        code, text = res if isinstance(res, tuple) else (1, str(res))
        self.voice_busy = False
        self.card_voice.toggle.setEnabled(True)
        if code == core.VOICE_NEED_PASSWORD:
            pw, ok = QInputDialog.getText(self, "Голос Discord",
                                          "Пароль sudo. Нужен, чтобы добавить или убрать правила iptables:",
                                          QLineEdit.Password)
            if ok and pw:
                self._voice_action(action, pw)
                return
        elif code != 0:
            QMessageBox.warning(self, "Голос Discord", text or "Хелпер завершился с ошибкой.")
        self._refresh_voice()

    def _update_test_info(self):
        self.test_info.setText(
            f"В списке {len(load_strategies())} стратегий. Каждая проверяется на адресах YouTube и "
            f"Discord с отпечатком браузера; ответ должен скачаться целиком, поэтому заморозка на "
            f"~16 КБ не пройдёт. Если одной стратегии мало, для сервисов соберутся отдельные правила. "
            f"Займёт от нескольких минут до четверти часа. Двойной клик по строке — применить.")

    def _fill_presets(self):
        """Комбобокс: лучшие из прошлого подбора + «свои аргументы»."""
        self.preset.clear()
        for fav in self.cfg.get("favorites", []):
            scores = " ".join(f"{SERVICE_TITLES.get(k, k)} {v[0]}/{v[1]}"
                              for k, v in sorted(fav.get("scores", {}).items()))
            kind = "раздельная · " if " -An " in fav["args"] else ""
            self.preset.addItem(f"{scores} · {kind}{fav['args']}", fav["args"])
        self.preset.addItem("Свои аргументы", None)
        args = self.dpi_args.text().strip()
        idx = self.preset.findData(args)
        self.preset.setCurrentIndex(idx if idx >= 0 else self.preset.count() - 1)

    def _set_args(self, args: str):
        self.dpi_args.setText(args)
        self.dpi_args.setCursorPosition(0)

    def _preset_chosen(self, idx: int):
        args = self.preset.itemData(idx)
        if args:
            self._set_args(args)
        else:
            self.dpi_args.setFocus()

    def _save(self):
        self.cfg.update(
            byedpi_port=self.dpi_port.value(),
            byedpi_args=self.dpi_args.text().strip(),
            fake_sni=self.fake_sni.text().strip() or "google.com",
            tg_port=self.tg_port.value(),
            tg_secret=self.tg_secret.text().strip(),
            tg_extra_args=self.tg_extra.text().strip(),
        )
        save_cfg(self.cfg)

    def _save_opts(self):
        self.cfg.update(autostart_byedpi=self.cb_auto_dpi.isChecked(),
                        autostart_tg=self.cb_auto_tg.isChecked(),
                        start_hidden=self.cb_hidden.isChecked())
        save_cfg(self.cfg)

    def _log(self, which: str, text: str):
        view = {"dpi": self.log_dpi, "tg": self.log_tg}[which]
        view.appendPlainText(text.rstrip("\n"))

    def _bg(self, fn, on_done):
        w = Worker(fn)
        w.finished_with.connect(on_done)
        w.finished.connect(lambda: self._workers.remove(w) if w in self._workers else None)
        self._workers.append(w)
        w.start()

    def _refresh_tray(self):
        on_d = self.p_dpi.state() != QProcess.NotRunning or self.tun_on
        on_t = self.p_tg.state() != QProcess.NotRunning
        if self.tray:
            self.tray.setIcon(tray_icon(on_d, on_t))
            self.act_dpi.setChecked(on_d)
            self.act_tg.setChecked(on_t)
            self.tray.setToolTip(f"{APP_NAME}\nСайты: {'вкл' if on_d else 'выкл'}"
                                 f"\nTelegram: {'вкл' if on_t else 'выкл'}")
        for w in (self.dpi_port, self.dpi_args, self.preset, self.fake_sni):
            w.setEnabled(not on_d)
        for w in (self.tg_port, self.tg_secret, self.tg_extra):
            w.setEnabled(not on_t)

    # ---------- процессы ----------

    def start_dpi(self):
        if self.p_dpi.state() != QProcess.NotRunning:
            return
        if self.tun_on:
            self.statusBar().showMessage("Работает режим TUN: byedpi уже слушает порт SOCKS", 4000)
            self._refresh_tray()
            return
        self._save()
        port = self.dpi_port.value()
        if port_busy(port):
            self.card_dpi.set_state("err", f"Порт {port} уже занят")
            return
        try:
            args = core.build_argv(port, self.dpi_args.text(), self.fake_sni.text().strip(),
                                   bool(self.cfg.get("ipv4_only", True)), log_level=1)
        except ValueError as e:
            self.card_dpi.set_state("err", f"Аргументы: {e}")
            return
        self._log("dpi", f"$ ciadpi {shlex.join(args)}")
        self.card_dpi.set_state("wait")
        self.p_dpi.start(str(CIADPI), args)

    def stop_dpi(self):
        self._stop_proc(self.p_dpi)

    def start_tg(self):
        if self.p_tg.state() != QProcess.NotRunning:
            return
        secret = self.tg_secret.text().strip()
        try:
            ok = len(secret) == 32 and bytes.fromhex(secret)
        except ValueError:
            ok = False
        if not ok:
            self.card_tg.set_state("err", "Secret: нужно 32 hex-символа")
            return
        self._save()
        port = self.tg_port.value()
        if port_busy(port):
            self.card_tg.set_state("err", f"Порт {port} уже занят")
            return
        try:
            extra = shlex.split(self.tg_extra.text())
        except ValueError as e:
            self.card_tg.set_state("err", f"Флаги: {e}")
            return
        args = ["-u", "-m", "proxy.tg_ws_proxy", "--host", "127.0.0.1",
                "--port", str(port), "--secret", secret, *extra]
        self.p_tg.setWorkingDirectory(str(TGWS_DIR))
        self._log("tg", "$ python " + " ".join(args).replace(secret, secret[:4] + "…"))
        self.card_tg.set_state("wait")
        self.p_tg.start(self._python(), args)

    def stop_tg(self):
        self._stop_proc(self.p_tg)

    def _stop_proc(self, proc: QProcess):
        if proc.state() == QProcess.NotRunning:
            return
        self._user_stopped.add(id(proc))
        proc.terminate()
        if not proc.waitForFinished(2500):
            proc.kill()
            proc.waitForFinished(1000)

    def _read(self, proc: QProcess, name: str):
        data = bytes(proc.readAllStandardOutput()).decode("utf-8", "replace")
        self._log(name, data)

    def _started(self, name: str):
        card = self.card_dpi if name == "dpi" else self.card_tg
        port = self.dpi_port.value() if name == "dpi" else self.tg_port.value()
        proc = self.p_dpi if name == "dpi" else self.p_tg
        tries = [0]

        # «работает» — когда порт реально начал слушать
        def probe():
            if proc.state() == QProcess.NotRunning:
                return
            if port_busy(port):
                card.set_state("on", f"Работает · 127.0.0.1:{port}")
                self._refresh_tray()
            elif tries[0] < 50:
                tries[0] += 1
                QTimer.singleShot(100, probe)
            else:
                card.set_state("err", "Процесс запущен, но порт не слушает")
        QTimer.singleShot(100, probe)
        self._refresh_tray()

    def _finished(self, name: str, code: int, status):
        card = self.card_dpi if name == "dpi" else self.card_tg
        proc = self.p_dpi if name == "dpi" else self.p_tg
        if self.quitting:
            return
        stopped_by_us = id(proc) in self._user_stopped
        self._user_stopped.discard(id(proc))
        if stopped_by_us or (status == QProcess.NormalExit and code == 0):
            card.set_state("off")
        else:
            card.set_state("err", f"Упал (код {code}) — смотри лог")
        self._log(name, f"— процесс завершён (код {code})")
        self._refresh_tray()

    def _error(self, name: str, err):
        if err == QProcess.FailedToStart:
            card = self.card_dpi if name == "dpi" else self.card_tg
            card.set_state("err", "Не удалось запустить — проверь установку")
            self._log(name, "Не удалось запустить процесс. Запусти install.sh.")
            self._refresh_tray()

    # ---------- действия ----------

    def open_in_telegram(self):
        if self.p_tg.state() == QProcess.NotRunning:
            self.start_tg()
        if not QProcess.startDetached("xdg-open", [self._tg_link()]):
            self._copy(self._tg_link("https://t.me/proxy"),
                       "xdg-open не сработал — ссылка скопирована, отправь её себе в Избранное")

    def launch_browser(self, url: str | None = None):
        if self.p_dpi.state() == QProcess.NotRunning:
            self.start_dpi()
        port = self.dpi_port.value()
        cmd = core.browser_command(self.cfg, port, url)
        if not cmd:
            QMessageBox.information(
                self, APP_NAME,
                f"Браузер не найден.\n\nУкажи команду в {CFG_FILE} (ключ browser_cmd), например:\n"
                "  brave-browser --proxy-server=socks5://127.0.0.1:{port}\n\n"
                f"Или пропиши прокси вручную: SOCKS5, 127.0.0.1, порт {port}.")
            return
        QProcess.startDetached(cmd[0], cmd[1:])

    def launch_discord(self):
        if self.p_dpi.state() == QProcess.NotRunning:
            self.start_dpi()
        cmd = core.discord_command(self.cfg, self.dpi_port.value())
        if cmd:
            QProcess.startDetached(cmd[0], cmd[1:])
            self.statusBar().showMessage("Discord запущен через прокси. Если он уже был открыт, "
                                         "полностью закрой его и нажми ещё раз.", 8000)
        else:
            self.statusBar().showMessage("Клиент Discord не найден, открываю в браузере", 6000)
            self.launch_browser("https://discord.com/app")

    def setup_pac(self):
        path = core.write_pac(self.dpi_port.value(), self.cfg.get("extra_proxy_domains"))
        url = f"file://{path}"
        QGuiApplication.clipboard().setText(url)
        QMessageBox.information(
            self, APP_NAME,
            f"Файл создан, адрес скопирован в буфер:\n{url}\n\n"
            "В Firefox: Настройки → Параметры сети → «URL автоматической настройки прокси», "
            "вставь адрес и нажми «Обновить».\n\n"
            "Через byedpi пойдут только YouTube и Discord. Если прокси выключен, браузер откроет "
            "их напрямую. Поля ручной настройки при этом не используются.\n\n"
            "Если сменишь порт SOCKS5, нажми эту кнопку ещё раз.")

    def check_now(self):
        if self.p_dpi.state() == QProcess.NotRunning and not self.tun_on:
            self.statusBar().showMessage("Сначала запусти byedpi", 3000)
            return
        self.btn_check.setEnabled(False)
        self.statusBar().showMessage("Проверяю YouTube и Discord через прокси…")
        port = self.dpi_port.value()
        cfg = dict(self.cfg)

        def run():
            targets = core.all_targets(cfg, core.discover_video_node(port))
            return core.check_targets(port, targets, float(cfg.get("probe_timeout", 8)),
                                      cfg.get("probe_fingerprint", "firefox"))

        def done(probes):
            self.btn_check.setEnabled(True)
            scores = core.summarize(probes)
            self.statusBar().showMessage(
                "  ·  ".join(f"{SERVICE_TITLES[k]}: {v[0]}/{v[1]}" for k, v in sorted(scores.items())),
                15000)
            lines = []
            for svc in sorted(scores):
                lines.append(f"{SERVICE_TITLES[svc]}: {scores[svc][0]} из {scores[svc][1]}")
                lines += [f"   {'✓' if p.ok else '✗'} {p.target.name}"
                          + ("" if p.ok else f": {REASONS[p.reason]}")
                          for p in probes if p.target.service == svc]
            if self.vpn_dev:
                lines += ["", VPN_WARNING.format(dev=self.vpn_dev)]
            QMessageBox.information(self, "Проверка сервисов", "\n".join(lines))
        self._bg(run, done)

    def make_report(self):
        self.btn_report.setEnabled(False)
        self.statusBar().showMessage("Собираю отчёт…")
        cfg = dict(self.cfg)

        def run():
            lines: list[str] = []
            core.diagnose(cfg, lines.append)
            CFG_DIR.mkdir(parents=True, exist_ok=True)
            REPORT_FILE.write_text("\n".join(lines) + "\n")
            return "\n".join(lines)

        def done(text):
            self.btn_report.setEnabled(True)
            self.statusBar().showMessage(f"Отчёт сохранён: {REPORT_FILE}", 10000)
            QGuiApplication.clipboard().setText(text)
            self._log("dpi", text)
            self.tabs.setCurrentWidget(self.log_dpi)
        self._bg(run, done)

    # ---------- подбор стратегий ----------

    def run_tester(self):
        if self.tester and self.tester.isRunning():
            self.tester.stop()
            self.btn_test.setText("Останавливаю…")
            self.btn_test.setEnabled(False)
            return
        if not shutil.which("curl"):
            QMessageBox.warning(self, APP_NAME, "Нужен curl: sudo xbps-install curl")
            return
        if core.tun_status().running:
            QMessageBox.warning(self, APP_NAME,
                                "Работает режим TUN. Временные ciadpi подбора сами пойдут через туннель, "
                                "и результат будет неверным. Останови TUN на время подбора.")
            return
        self._refresh_vpn()
        if self.vpn_dev:
            answer = QMessageBox.warning(
                self, APP_NAME,
                VPN_WARNING.format(dev=self.vpn_dev) + "\n\nВсё равно запустить подбор?",
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if answer != QMessageBox.Yes:
                return
        self._save()
        strategies = load_strategies()
        own = self.dpi_args.text().strip()
        if own and own not in strategies:
            strategies.insert(0, own)
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)
        self.test_bar.setRange(0, len(strategies))
        self.test_bar.setValue(0)
        self.test_bar.show()
        self.tester = StrategyTester(strategies, dict(self.cfg), self.fake_sni.text().strip(), own)
        self.tester.progress.connect(self._test_progress)
        self.tester.row.connect(self._test_result)
        self.tester.failed.connect(lambda m: QMessageBox.warning(self, APP_NAME, m))
        self.tester.done.connect(self._test_done)
        self.btn_test.setText("Остановить подбор")
        self.btn_update.setEnabled(False)
        self.tabs.setCurrentIndex(0)
        self.tester.start()

    def _test_progress(self, i: int, n: int, args: str):
        self.test_bar.setRange(0, n)
        self.test_bar.setValue(i)
        self.test_bar.setFormat(f"{i + 1}/{n}  {args[:60]}")

    def _test_result(self, row: Row):
        self.table.setSortingEnabled(False)     # иначе строка пересортируется посреди заполнения
        r = self.table.rowCount()
        self.table.insertRow(r)
        for col, svc in enumerate(("youtube", "discord")):
            ok, total = row.scores.get(svc, (0, 0))
            item = ScoreItem(ok, total)
            self.table.setItem(r, col, item)
        args_item = QTableWidgetItem(row.args)
        args_item.setToolTip("\n".join(row.fails) or "Все адреса прошли")
        self.table.setItem(r, 2, args_item)

    def _test_done(self, rows: list[Row], best: Row | None, stopped: bool):
        self.btn_test.setText("Подобрать стратегию")
        self.btn_test.setEnabled(True)
        self.btn_update.setEnabled(True)
        self.test_bar.hide()
        self.table.setSortingEnabled(True)
        self.table.sortItems(0, Qt.DescendingOrder)
        if self.quitting:
            return
        if not best:
            self.statusBar().showMessage(
                "Ни одна стратегия не прошла. Нажми «Проверить DNS» — возможно, дело не в DPI.", 15000)
            return
        ordered = [best, *[r for r in rank(rows) if r.args != best.args and r.total > 0]]
        self.cfg["favorites"] = [r.to_favorite() for r in ordered[:8]]
        was_on = self.p_dpi.state() != QProcess.NotRunning
        if was_on:
            self.stop_dpi()
        self._set_args(best.args)
        self._fill_presets()
        self._save()
        for r in range(self.table.rowCount()):
            if self.table.item(r, 2).text() == best.args:
                self.table.selectRow(r)
                break
        if was_on:
            QTimer.singleShot(300, self.start_dpi)
        scores = ", ".join(f"{SERVICE_TITLES[k]} {v[0]}/{v[1]}" for k, v in sorted(best.scores.items()))
        kind = "Применены раздельные правила" if best.kind == "combo" else "Применена стратегия"
        self.statusBar().showMessage(f"{kind}: {scores}", 15000)

    def _apply_selected(self):
        rows = self.table.selectionModel().selectedRows()
        if not rows:
            return
        args = self.table.item(rows[0].row(), 2).text()
        was_on = self.p_dpi.state() != QProcess.NotRunning
        if was_on:
            self.stop_dpi()
        self._set_args(args)
        self._fill_presets()
        self._save()
        if was_on:
            QTimer.singleShot(300, self.start_dpi)
        self.statusBar().showMessage("Стратегия применена", 4000)

    def update_strategies(self):
        self.btn_update.setEnabled(False)
        port = self.dpi_port.value() if self.p_dpi.state() != QProcess.NotRunning else None

        def fetch():
            for via in [None] + ([port] if port else []):
                cmd = ["curl", "-sfL", "-m", "15", STRATEGIES_URL]
                if via:
                    cmd[1:1] = ["-x", f"socks5h://127.0.0.1:{via}"]
                try:
                    out = subprocess.run(cmd, capture_output=True, text=True, timeout=20).stdout
                except (OSError, subprocess.TimeoutExpired):
                    continue
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                if len(lines) >= 5 and all(l.startswith("-") for l in lines):
                    return lines
            return None

        def done(lines):
            self.btn_update.setEnabled(True)
            if not lines:
                QMessageBox.warning(self, APP_NAME, "Не удалось скачать список с GitHub.")
                return
            CFG_DIR.mkdir(parents=True, exist_ok=True)
            USER_STRATEGIES.write_text("\n".join(lines) + "\n")
            self._update_test_info()
            self.statusBar().showMessage(f"Список обновлён: {len(lines)} стратегий", 6000)
        self._bg(fetch, done)

    # ---------- DNS ----------

    def check_dns(self):
        self.btn_dns.setEnabled(False)
        self.statusBar().showMessage("Проверяю DNS…")
        port = self.dpi_port.value() if self.p_dpi.state() != QProcess.NotRunning else None
        self._bg(lambda: core.check_dns(port), self._dns_done)

    def _dns_done(self, res: list[core.DnsResult]):
        self.btn_dns.setEnabled(True)
        self.statusBar().clearMessage()
        lines = [f"<b>{r.host}</b><br>&nbsp;&nbsp;система: {', '.join(r.system[:3]) or '—'}"
                 f"<br>&nbsp;&nbsp;DoH: {', '.join(r.doh[:3]) or 'не ответил'}"
                 f"<br>&nbsp;&nbsp;{'✗' if r.bad else '✓'} {r.verdict}" for r in res]
        if any(r.bad for r in res):
            summary = ("<p><b>Проблема в DNS, а не в стратегии.</b> byedpi спрашивает адреса у "
                       "системного резолвера — если он врёт, никакая стратегия не поможет.</p>"
                       "<p>Решение для Void — локальный шифрованный DNS:<br>"
                       "<code>sudo xbps-install dnscrypt-proxy<br>"
                       "sudo ln -s /etc/sv/dnscrypt-proxy /var/service/</code><br>"
                       "и в <code>/etc/resolv.conf</code> оставить <code>nameserver 127.0.0.1</code>. "
                       "Подробнее — в README.</p>")
        else:
            summary = "<p><b>DNS в порядке</b> — дело в DPI. Запусти «Подобрать стратегию».</p>"
        box = QMessageBox(self)
        box.setWindowTitle("Проверка DNS")
        box.setTextFormat(Qt.RichText)
        box.setText(summary + "<br>".join(lines))
        box.exec()

    # ---------- окно / выход ----------

    def _show(self):
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def _toggle_window(self):
        self.hide() if self.isVisible() else self._show()

    def closeEvent(self, e):
        if self.tray and not self.quitting:
            e.ignore()
            self.hide()
            self.tray.showMessage(APP_NAME, "Работаю в трее. Выход — через меню иконки.",
                                  QSystemTrayIcon.Information, 2500)
        else:
            self.quit_app()
            e.accept()

    def quit_app(self):
        self.quitting = True
        self._save()
        if self.tester and self.tester.isRunning():
            self.tester.stop()
            self.tester.wait(20000)
        for w in list(self._workers):
            w.wait(30000)
        self.stop_dpi()
        self.stop_tg()
        QApplication.quit()


STYLE = """
QWidget { font-size: 10pt; }
#card { background: palette(alternate-base); border-radius: 12px; }
#cardTitle { font-weight: 600; font-size: 11pt; }
#status, #hint { color: palette(placeholder-text); }
#warn { background: #4a3413; color: #ffcf87; border-radius: 8px; padding: 8px 12px; }
QPushButton { padding: 6px 12px; border-radius: 8px; background: palette(button); }
QPushButton:hover { background: palette(mid); }
QPushButton:disabled { color: palette(placeholder-text); }
QPushButton#toggle:checked { background: #2e7d32; color: white; }
QPushButton#accent { background: #2aa3e6; color: white; }
QLineEdit, QSpinBox, QComboBox { padding: 4px 6px; border-radius: 6px; }
QPlainTextEdit, QTableWidget { border-radius: 8px; }
QProgressBar { border-radius: 6px; text-align: center; height: 18px; }
QProgressBar::chunk { background: #2aa3e6; border-radius: 6px; }
"""


def dark_palette() -> QPalette:
    p = QPalette()
    base, alt, text = QColor("#1b1d22"), QColor("#262930"), QColor("#e6e6e6")
    p.setColor(QPalette.Window, base)
    p.setColor(QPalette.WindowText, text)
    p.setColor(QPalette.Base, QColor("#15171b"))
    p.setColor(QPalette.AlternateBase, alt)
    p.setColor(QPalette.Text, text)
    p.setColor(QPalette.Button, QColor("#30343c"))
    p.setColor(QPalette.ButtonText, text)
    p.setColor(QPalette.Mid, QColor("#3a3f48"))
    p.setColor(QPalette.Highlight, QColor("#2aa3e6"))
    p.setColor(QPalette.HighlightedText, QColor("white"))
    p.setColor(QPalette.ToolTipBase, alt)
    p.setColor(QPalette.ToolTipText, text)
    p.setColor(QPalette.PlaceholderText, QColor("#8a8f99"))
    for role in (QPalette.Text, QPalette.ButtonText, QPalette.WindowText):
        p.setColor(QPalette.Disabled, role, QColor("#6b7079"))
    return p


def main():
    QApplication.setApplicationName("byedpi-tg")
    QApplication.setDesktopFileName("byedpi-tg")
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    app.setStyle("Fusion")
    if os.environ.get("BYEDPI_TG_LIGHT") != "1":
        app.setPalette(dark_palette())
    app.setStyleSheet(STYLE)
    app.setWindowIcon(tray_icon(True, True))

    w = MainWindow()
    signal.signal(signal.SIGINT, lambda *_: w.quit_app())
    signal.signal(signal.SIGTERM, lambda *_: w.quit_app())
    # чтобы Python успевал обработать сигнал внутри цикла Qt
    t = QTimer()
    t.timeout.connect(lambda: None)
    t.start(300)

    if not (w.cfg["start_hidden"] and w.tray) or "--show" in sys.argv:
        w.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
