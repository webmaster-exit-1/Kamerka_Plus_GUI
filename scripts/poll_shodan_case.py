#!/usr/bin/env python3
import os
import sys
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "kamerka.settings")

import django

django.setup()

from celery.result import AsyncResult
from kamerka.celery import app
from app_kamerka.models import Device


def main():
    tid = sys.argv[1] if len(sys.argv) > 1 else None
    case_id = int(sys.argv[2]) if len(sys.argv) > 2 else 18
    if not tid:
        print("usage: poll_shodan_case.py <task_id> [case_id]")
        return 1
    for i in range(180):
        r = AsyncResult(tid, app=app)
        if r.state in ("SUCCESS", "FAILURE"):
            print("done", r.state, "result", r.result)
            break
        if i % 6 == 0:
            n = Device.objects.filter(search_id=case_id).count()
            print("poll", i, r.state, "devices", n)
        time.sleep(5)
    else:
        print("timeout")
    n = Device.objects.filter(search_id=case_id).count()
    print("final_devices", n)
    return 0


if __name__ == "__main__":
    sys.exit(main())