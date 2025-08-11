translations = {
    "en": {
        "app_title": "Scanner",
        "status_running": "Application is running...",
        "status_error": "An error occurred.",
    },
    "pl": {
        "app_title": "Skaner",
        "status_running": "Aplikacja działa...",
        "status_error": "Wystąpił błąd.",
    }
}

current_lang = "pl"

def t(key):
    return translations.get(current_lang, {}).get(key, key)
