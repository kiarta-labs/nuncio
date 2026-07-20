"""Email delivery adapter."""
from nuncio.delivery.email import Email


class FakeSMTP:
    """Records login/send_message calls; supports the `with ... :` protocol
    the adapter uses."""
    instances = []

    def __init__(self, host, port, timeout, tls):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.tls = tls
        self.logged_in = None
        self.sent = []
        FakeSMTP.instances.append(self)

    def login(self, user, password):
        self.logged_in = (user, password)

    def send_message(self, msg):
        self.sent.append(msg)

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def factory():
    FakeSMTP.instances = []
    return FakeSMTP


def base_cfg(**overrides):
    cfg = {
        "smtp_host": "smtp.example.com", "smtp_port": 587,
        "user": "", "password": "", "from_addr": "nuncio@example.com",
        "to": "you@example.com", "tls": "starttls",
    }
    cfg.update(overrides)
    return cfg


def test_multipart_alternative_when_html_present():
    Factory = factory()
    a = Email(base_cfg(), smtp_factory=Factory)
    assert a.send("Alert", "plain body", "critical", html="<p>hi</p>") is True
    msg = Factory.instances[0].sent[0]
    assert msg.is_multipart()
    html_parts = [p for p in msg.walk() if p.get_content_type() == "text/html"]
    assert html_parts


def test_plain_only_when_html_is_none():
    Factory = factory()
    a = Email(base_cfg(), smtp_factory=Factory)
    assert a.send("Alert", "plain body", "critical") is True
    msg = Factory.instances[0].sent[0]
    assert not msg.is_multipart()


def test_tls_starttls_default():
    Factory = factory()
    a = Email(base_cfg(), smtp_factory=Factory)
    a.send("t", "b")
    assert Factory.instances[0].tls == "starttls"


def test_tls_ssl_branch_via_injected_factory():
    Factory = factory()
    a = Email(base_cfg(tls="ssl"), smtp_factory=Factory)
    a.send("t", "b")
    assert Factory.instances[0].tls == "ssl"


def test_tls_none_branch_via_injected_factory():
    Factory = factory()
    a = Email(base_cfg(tls="none"), smtp_factory=Factory)
    a.send("t", "b")
    assert Factory.instances[0].tls == "none"


def test_login_called_only_when_user_and_password_set():
    Factory = factory()
    a = Email(base_cfg(user="u", password="p"), smtp_factory=Factory)
    a.send("t", "b")
    assert Factory.instances[0].logged_in == ("u", "p")


def test_login_skipped_when_user_or_password_missing():
    Factory = factory()
    a = Email(base_cfg(user="u", password=""), smtp_factory=Factory)
    a.send("t", "b")
    assert Factory.instances[0].logged_in is None


def test_unconfigured_missing_host_returns_false():
    a = Email(base_cfg(smtp_host=""), smtp_factory=factory())
    assert a.send("t", "b") is False


def test_unconfigured_missing_to_returns_false():
    a = Email(base_cfg(to=""), smtp_factory=factory())
    assert a.send("t", "b") is False


def test_smtp_exception_returns_false_not_raise():
    class BoomFactory:
        def __call__(self, *a, **k):
            raise ConnectionError("smtp down")
    a = Email(base_cfg(), smtp_factory=BoomFactory())
    assert a.send("t", "b") is False


def test_to_list_split_and_stripped():
    Factory = factory()
    a = Email(base_cfg(to="a@example.com, b@example.com"), smtp_factory=Factory)
    assert a.to == ["a@example.com", "b@example.com"]
    a.send("t", "b")
    assert Factory.instances[0].sent[0]["To"] == "a@example.com, b@example.com"


# --- subject header-injection guard ---

def test_subject_header_injection_sanitized():
    Factory = factory()
    a = Email(base_cfg(), smtp_factory=Factory)
    a.send("x\r\nBcc: evil@example.com", "body")
    msg = Factory.instances[0].sent[0]
    subjects = msg.get_all("Subject")
    assert len(subjects) == 1
    assert "\r" not in subjects[0] and "\n" not in subjects[0]
    assert "Bcc:" not in subjects[0] or "evil@example.com" not in (msg.get_all("Bcc") or [])
