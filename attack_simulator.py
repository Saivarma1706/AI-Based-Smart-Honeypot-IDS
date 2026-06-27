"""attack_simulator

Phase 3 - Attack Simulation Engine

Generates realistic honeypot traffic against the existing Flask
multi-service endpoints (and therefore reuses the existing pipeline):

- brute_force     -> /ssh
- password_spray  -> /database
- api_abuse       -> /api/auth
- stealth         -> /server

Design goals:
- Uses `requests` library
- Triggers existing detection pipeline by calling the real Flask routes,
  which then call `process_security_event()`.

Run examples:
  python attack_simulator.py --attack brute_force --url http://127.0.0.1:5000
  python attack_simulator.py --attack password_spray --url http://127.0.0.1:5000
  python attack_simulator.py --attack api_abuse --url http://127.0.0.1:5000
  python attack_simulator.py --attack stealth --url http://127.0.0.1:5000
"""

from __future__ import annotations

import argparse
import time
from dataclasses import dataclass
from typing import Any, Literal

import re
import requests





AttackType = Literal["brute_force", "password_spray", "api_abuse", "stealth"]


@dataclass(frozen=True)
class AttackSummary:
    attack_type: str
    target: str
    attempts_sent: int
    successful_requests: int
    failed_requests: int
    duration_seconds: float

    def to_pretty_lines(self) -> str:
        return (
            "\n[attack_simulator] Attack Summary\n"
            f"- Attack Type: {self.attack_type}\n"
            f"- Target: {self.target}\n"
            f"- Attempts Sent: {self.attempts_sent}\n"
            f"- Successful Requests: {self.successful_requests}\n"
            f"- Failed Requests: {self.failed_requests}\n"
            f"- Duration: {self.duration_seconds:.2f}s\n"
        )


def _sleep(delay_seconds: float) -> None:
    if delay_seconds and delay_seconds > 0:
        time.sleep(delay_seconds)


def _extract_csrf_token(html_text: str) -> str | None:
    # Avoid external HTML parsers; extract CSRF hidden input value.
    # templates render: <input ... name="csrf_token" value="...">
    # Be robust to single/double quotes and whitespace.
    m = re.search(
        r"name=[\"']csrf_token[\"']\s+[^>]*?value=[\"']([^\"']+)[\"']",
        html_text,
        flags=re.IGNORECASE,
    )
    if not m:
        return None
    return m.group(1)




def _post_form(session: requests.Session, url: str, data: dict[str, Any], timeout: float) -> requests.Response:
    return session.post(url, data=data, timeout=timeout)


def _post_json(session: requests.Session, url: str, payload: dict[str, Any], timeout: float) -> requests.Response:
    return session.post(url, json=payload, timeout=timeout)


def _get_csrf(session: requests.Session, url: str, timeout: float) -> str | None:
    try:
        resp = session.get(url, timeout=timeout)
        return _extract_csrf_token(resp.text)
    except requests.RequestException:
        return None


def _run_attack(
    *,
    session: requests.Session,
    target_path: str,
    url_base: str,
    delay_seconds: float,
    attempts: int,
    request_builder,
    success_status_predicate,
    timeout: float,
) -> AttackSummary:
    target_url = url_base.rstrip("/") + target_path

    ok = 0
    fail = 0

    start = time.time()
    for i in range(attempts):
        req_kwargs = request_builder(i)
        try:
            resp = req_kwargs["fn"](session, target_url, req_kwargs["data"], timeout)
            if success_status_predicate(resp):
                ok += 1
            else:
                fail += 1
        except requests.RequestException:
            fail += 1

        _sleep(delay_seconds)

    duration = time.time() - start
    return AttackSummary(
        attack_type=str(target_path),
        target=target_path,
        attempts_sent=attempts,
        successful_requests=ok,
        failed_requests=fail,
        duration_seconds=duration,
    )


def simulate_brute_force(
    *,
    session: requests.Session,
    url_base: str,
    attempts: int,
    delay_seconds: float,
    ssh_username: str,
    ssh_passwords: list[str],
    timeout: float,
) -> AttackSummary:
    target_path = "/ssh"

    csrf = _get_csrf(session, url_base.rstrip("/") + target_path, timeout)

    def builder(i: int):
        pw = ssh_passwords[i % len(ssh_passwords)]
        data = {"username": ssh_username, "password": pw}
        if csrf:
            data["csrf_token"] = csrf
        return {"fn": _post_form, "data": data}

    def is_success(resp: requests.Response) -> bool:
        # Route returns HTTP 200 for both success/failure; distinguish via body.
        if resp.status_code < 200 or resp.status_code >= 300:
            return False
        text = resp.text or ""
        return "Access Granted" in text

    summary = _run_attack(
        session=session,
        target_path=target_path,
        url_base=url_base,
        delay_seconds=delay_seconds,
        attempts=attempts,
        request_builder=builder,
        success_status_predicate=is_success,
        timeout=timeout,
    )
    return AttackSummary(
        attack_type="brute_force",
        target=target_path,
        attempts_sent=summary.attempts_sent,
        successful_requests=summary.successful_requests,
        failed_requests=summary.failed_requests,
        duration_seconds=summary.duration_seconds,
    )



def simulate_password_spray(
    *,
    session: requests.Session,
    url_base: str,
    attempts: int,
    delay_seconds: float,
    db_usernames: list[str],
    spray_password: str,
    timeout: float,
) -> AttackSummary:
    target_path = "/database"

    csrf = _get_csrf(session, url_base.rstrip("/") + target_path, timeout)

    def builder(i: int):
        user = db_usernames[i % len(db_usernames)]
        data = {"username": user, "password": spray_password}
        if csrf:
            data["csrf_token"] = csrf
        return {"fn": _post_form, "data": data}

    def is_success(resp: requests.Response) -> bool:
        if resp.status_code < 200 or resp.status_code >= 300:
            return False
        text = resp.text or ""
        return "Database Session Established" in text

    summary = _run_attack(
        session=session,
        target_path=target_path,
        url_base=url_base,
        delay_seconds=delay_seconds,
        attempts=attempts,
        request_builder=builder,
        success_status_predicate=is_success,
        timeout=timeout,
    )
    return AttackSummary(
        attack_type="password_spray",
        target=target_path,
        attempts_sent=summary.attempts_sent,
        successful_requests=summary.successful_requests,
        failed_requests=summary.failed_requests,
        duration_seconds=summary.duration_seconds,
    )



def simulate_api_abuse(
    *,
    session: requests.Session,
    url_base: str,
    attempts: int,
    delay_seconds: float,
    api_username: str,
    api_password: str,
    timeout: float,
) -> AttackSummary:
    target_path = "/api/auth"

    def builder(i: int):
        return {"fn": _post_json, "data": {"username": api_username, "password": api_password}}

    def is_success(resp: requests.Response) -> bool:
        return resp.status_code == 200

    summary = _run_attack(
        session=session,
        target_path=target_path,
        url_base=url_base,
        delay_seconds=delay_seconds,
        attempts=attempts,
        request_builder=builder,
        success_status_predicate=is_success,
        timeout=timeout,
    )
    return AttackSummary(
        attack_type="api_abuse",
        target=target_path,
        attempts_sent=summary.attempts_sent,
        successful_requests=summary.successful_requests,
        failed_requests=summary.failed_requests,
        duration_seconds=summary.duration_seconds,
    )


def simulate_stealth_server(
    *,
    session: requests.Session,
    url_base: str,
    attempts: int,
    delay_seconds: float,
    server_username: str,
    server_password: str,
    timeout: float,
) -> AttackSummary:
    target_path = "/server"

    csrf = _get_csrf(session, url_base.rstrip("/") + target_path, timeout)

    def builder(i: int):
        data = {"username": server_username, "password": server_password}
        if csrf:
            data["csrf_token"] = csrf
        return {"fn": _post_form, "data": data}

    def is_success(resp: requests.Response) -> bool:
        if resp.status_code < 200 or resp.status_code >= 300:
            return False
        text = resp.text or ""
        # server template renders: <div ...>Console Unlocked</div>
        return "Console Unlocked" in text

    summary = _run_attack(
        session=session,
        target_path=target_path,
        url_base=url_base,
        delay_seconds=delay_seconds,
        attempts=attempts,
        request_builder=builder,
        success_status_predicate=is_success,
        timeout=timeout,
    )

    return AttackSummary(
        attack_type="stealth",
        target=target_path,
        attempts_sent=summary.attempts_sent,
        successful_requests=summary.successful_requests,
        failed_requests=summary.failed_requests,
        duration_seconds=summary.duration_seconds,
    )



def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Phase 3 Attack Simulation Engine (honeypot traffic generator)")

    p.add_argument("--url", required=True, help="Base URL of the Flask server (e.g., http://127.0.0.1:5000)")
    p.add_argument(
        "--attack",
        required=True,
        choices=["brute_force", "password_spray", "api_abuse", "stealth"],
        help="Attack type",
    )

    p.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between requests")
    p.add_argument("--attempts", type=int, default=10, help="Number of attempts/requests to send")

    # Optional defaults
    p.add_argument("--ssh-username", default="sys_admin")
    p.add_argument("--ssh-passwords", default="wrong1,wrong2,wrong3,wrong4")

    p.add_argument("--db-usernames", default="user1,user2,user3,user4,user5")
    p.add_argument("--spray-password", default="wrong-pass")

    p.add_argument("--api-username", default="sys_admin")
    p.add_argument("--api-password", default="wrong-pass")

    p.add_argument("--server-username", default="sys_admin")
    p.add_argument("--server-password", default="wrong-pass")

    p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (seconds)")

    return p.parse_args()


def main() -> None:
    args = _parse_args()

    ssh_passwords = [x.strip() for x in args.ssh_passwords.split(",") if x.strip()]
    db_usernames = [x.strip() for x in args.db_usernames.split(",") if x.strip()]

    with requests.Session() as session:
        if args.attack == "brute_force":
            summary = simulate_brute_force(
                session=session,
                url_base=args.url,
                attempts=args.attempts,
                delay_seconds=args.delay,
                ssh_username=args.ssh_username,
                ssh_passwords=ssh_passwords,
                timeout=args.timeout,
            )
        elif args.attack == "password_spray":
            summary = simulate_password_spray(
                session=session,
                url_base=args.url,
                attempts=args.attempts,
                delay_seconds=args.delay,
                db_usernames=db_usernames,
                spray_password=args.spray_password,
                timeout=args.timeout,
            )
        elif args.attack == "api_abuse":
            summary = simulate_api_abuse(
                session=session,
                url_base=args.url,
                attempts=args.attempts,
                delay_seconds=args.delay,
                api_username=args.api_username,
                api_password=args.api_password,
                timeout=args.timeout,
            )
        elif args.attack == "stealth":
            summary = simulate_stealth_server(
                session=session,
                url_base=args.url,
                attempts=args.attempts,
                delay_seconds=args.delay,
                server_username=args.server_username,
                server_password=args.server_password,
                timeout=args.timeout,
            )
        else:
            raise ValueError(f"Unknown attack: {args.attack}")

    print(summary.to_pretty_lines())


if __name__ == "__main__":
    main()

