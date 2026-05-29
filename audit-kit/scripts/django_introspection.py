#!/usr/bin/env python3
from __future__ import annotations

import importlib
import json
import os
import sys
from pathlib import Path
from typing import Any


SECRET_KEYS = {"SECRET_KEY", "PASSWORD", "TOKEN", "KEY", "SECRET", "API_KEY", "ACCESS_KEY"}
TOPOLOGY_KEYS = {"HOST", "USER", "NAME", "LOCATION", "PORT", "OPTIONS"}
PATH_KEYS = {"DIR", "DIRS", "PATH", "PATHS", "ROOT", "BASE_DIR"}


def redacted(key: str, value: Any) -> Any:
    upper = key.upper()
    if any(marker in upper for marker in SECRET_KEYS) or upper in TOPOLOGY_KEYS or upper in PATH_KEYS:
        if isinstance(value, (list, tuple)):
            return ["<redacted>" if item not in (None, "") else item for item in value]
        return "<redacted>" if value not in (None, "") else value
    if isinstance(value, dict):
        return {str(k): redacted(str(k), v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redacted(key, item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return value.as_posix()
    return object_name(value)


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def callback_path(callback: Any) -> str:
    view_class = getattr(callback, "view_class", None) or getattr(callback, "cls", None)
    if view_class is not None:
        return f"{view_class.__module__}.{view_class.__name__}"
    module = getattr(callback, "__module__", "")
    name = getattr(callback, "__name__", callback.__class__.__name__)
    return f"{module}.{name}" if module else name


def object_name(value: Any) -> str:
    if isinstance(value, str):
        return value
    module = getattr(value, "__module__", "")
    name = getattr(value, "__name__", value.__class__.__name__)
    return f"{module}.{name}" if module else name


def named_list(value: Any) -> list[str]:
    return [object_name(item) for item in as_list(value)]


def redacted_list(value: Any) -> list[Any]:
    return [redacted("HOST", item) for item in as_list(value)]


def json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(k): json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    if isinstance(value, Path):
        return value.as_posix()
    return object_name(value)


def drf_metadata(callback: Any) -> dict[str, Any]:
    view_class = getattr(callback, "view_class", None) or getattr(callback, "cls", None)
    source = view_class or callback
    return {
        "permission_classes": named_list(getattr(source, "permission_classes", [])),
        "authentication_classes": named_list(getattr(source, "authentication_classes", [])),
        "throttle_classes": named_list(getattr(source, "throttle_classes", [])),
        "serializer_class": object_name(getattr(source, "serializer_class", "")) if getattr(source, "serializer_class", "") else "",
        "actions": redacted("actions", getattr(callback, "actions", {})),
    }


def route_pattern(pattern: Any) -> str:
    route = getattr(getattr(pattern, "pattern", None), "_route", None)
    if route is not None:
        return str(route)
    return str(getattr(pattern, "pattern", pattern))


def flatten_urls(patterns: list[Any], prefix: str = "", namespace: str = "") -> list[dict[str, Any]]:
    rows = []
    for item in patterns:
        route = f"{prefix}{route_pattern(item)}"
        nested = getattr(item, "url_patterns", None)
        item_namespace = getattr(item, "namespace", None) or namespace
        if nested is not None:
            rows.extend(flatten_urls(list(nested), route, item_namespace))
            continue
        rows.append(
            {
                "pattern": route,
                "name": getattr(item, "name", None) or "",
                "namespace": item_namespace or "",
                "callback": callback_path(getattr(item, "callback", None)),
                "drf": drf_metadata(getattr(item, "callback", None)),
            }
        )
    return rows


def setup_django(project: Path, settings_module: str) -> Any:
    old_settings = os.environ.get("DJANGO_SETTINGS_MODULE")
    try:
        os.environ["DJANGO_SETTINGS_MODULE"] = settings_module
        django = importlib.import_module("django")
        setup = getattr(django, "setup", None)
        if setup is not None:
            setup()
        return importlib.import_module("django.conf").settings
    finally:
        if old_settings is None:
            os.environ.pop("DJANGO_SETTINGS_MODULE", None)
        else:
            os.environ["DJANGO_SETTINGS_MODULE"] = old_settings


def collect(project: Path, settings_module: str) -> dict[str, Any]:
    project_path = str(project)
    sys.path.insert(0, project_path)
    try:
        settings = setup_django(project, settings_module)
        rest_framework = getattr(settings, "REST_FRAMEWORK", {}) or {}
        root_urlconf = getattr(settings, "ROOT_URLCONF", "")
        urlconf = importlib.import_module(root_urlconf) if root_urlconf else None
        urls = flatten_urls(list(getattr(urlconf, "urlpatterns", []))) if urlconf else []
        return {
            "settings_module": settings_module,
            "settings": {
                "debug": bool(getattr(settings, "DEBUG", False)),
                "allowed_hosts": redacted_list(getattr(settings, "ALLOWED_HOSTS", [])),
                "installed_apps": as_list(getattr(settings, "INSTALLED_APPS", [])),
                "middleware": as_list(getattr(settings, "MIDDLEWARE", [])),
                "authentication_backends": as_list(getattr(settings, "AUTHENTICATION_BACKENDS", [])),
                "templates": redacted("TEMPLATES", getattr(settings, "TEMPLATES", [])),
                "databases": redacted("DATABASES", getattr(settings, "DATABASES", {})),
                "caches": redacted("CACHES", getattr(settings, "CACHES", {})),
                "secret_key": redacted("SECRET_KEY", getattr(settings, "SECRET_KEY", "")),
                "session_cookie_secure": bool(getattr(settings, "SESSION_COOKIE_SECURE", False)),
                "csrf_cookie_secure": bool(getattr(settings, "CSRF_COOKIE_SECURE", False)),
                "csrf_trusted_origins": redacted_list(getattr(settings, "CSRF_TRUSTED_ORIGINS", [])),
                "cors_allowed_origins": redacted_list(getattr(settings, "CORS_ALLOWED_ORIGINS", [])),
                "cors_allow_all_origins": bool(getattr(settings, "CORS_ALLOW_ALL_ORIGINS", False)),
            },
            "drf": {
                "installed": "rest_framework" in as_list(getattr(settings, "INSTALLED_APPS", [])),
                "default_authentication_classes": named_list(rest_framework.get("DEFAULT_AUTHENTICATION_CLASSES")),
                "default_permission_classes": named_list(rest_framework.get("DEFAULT_PERMISSION_CLASSES")),
                "default_throttle_classes": named_list(rest_framework.get("DEFAULT_THROTTLE_CLASSES")),
                "default_throttle_rates": json_safe(rest_framework.get("DEFAULT_THROTTLE_RATES", {})),
                "default_serializer_class": object_name(rest_framework.get("DEFAULT_SERIALIZER_CLASS", "")) if rest_framework.get("DEFAULT_SERIALIZER_CLASS", "") else "",
            },
            "urls": urls,
        }
    finally:
        if sys.path and sys.path[0] == project_path:
            sys.path.pop(0)


def write_artifacts(project: Path, settings_module: str, reports: Path) -> None:
    result = collect(project, settings_module)
    out = reports / "F2"
    out.mkdir(parents=True, exist_ok=True)
    settings_doc = {"settings_module": result["settings_module"], "settings": result["settings"], "drf": result["drf"]}
    urls_doc = {"settings_module": result["settings_module"], "urls": result["urls"]}
    (out / "django-settings.json").write_text(json.dumps(settings_doc, indent=2, sort_keys=True) + "\n")
    (out / "django-urls.json").write_text(json.dumps(urls_doc, indent=2, sort_keys=True) + "\n")


def main() -> None:
    if len(sys.argv) != 4:
        raise SystemExit("usage: django_introspection.py PROJECT SETTINGS_MODULE REPORTS_DIR")
    write_artifacts(Path(sys.argv[1]).resolve(), sys.argv[2], Path(sys.argv[3]).resolve())
    print(f"Django introspection: {Path(sys.argv[3]).resolve() / 'F2'}")


if __name__ == "__main__":
    main()
