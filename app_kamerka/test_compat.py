"""Django test-client compatibility shims (Python 3.14 + Django 4.2)."""

from __future__ import annotations

import sys


def apply_py314_django_test_patches() -> None:
    """Avoid RequestContext.__copy__ failures in Django's template_rendered hook."""
    if sys.version_info < (3, 14):
        return

    import copy as copy_mod

    from django.test import client as test_client

    if getattr(test_client, "_kamerka_py314_patched", False):
        return

    def store_rendered_templates(store, signal, sender, template, context, **kwargs):
        store.setdefault("templates", []).append(template)
        if "context" not in store:
            store["context"] = test_client.ContextList()
        try:
            store["context"].append(copy_mod.copy(context))
        except AttributeError:
            store["context"].append(context)

    test_client.store_rendered_templates = store_rendered_templates
    test_client._kamerka_py314_patched = True