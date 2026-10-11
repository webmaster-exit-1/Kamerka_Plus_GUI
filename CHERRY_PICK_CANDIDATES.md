# Cherry-pick candidates for a maintained Kamerka fork

This file is a planning reference for backporting only the useful parts of the upstream `woj-ciech/Kamerka-GUI` into a maintained fork. The goal is to cherry-pick ideas and functions, not whole commits or full rewrites.

Priority:
1. Search worker improvements
2. Honeypot filtering
3. Screenshot + indicator extraction
4. Gallery pagination/filtering
5. Screenshot modal UX
6. Security hygiene

---

## 1) Shodan worker: honeypot filtering and result handling

Source:
- `kamerka/tasks.py`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/kamerka/tasks.py#L586-L799

Why it fits:
- This code is a focused backend improvement that reduces noisy results without changing the app architecture.
- It adds honeypot detection and result parsing in the exact place where Shodan results are normalized and saved.
- It is useful for a fork that still uses the same Django + Celery + Shodan workflow.

Apply where:
- Your fork's `kamerka/tasks.py` or the equivalent background worker handling Shodan results.

```python
def shodan_search_worker(fk, query, search_type, category, country=None, coordinates=None, all_results=False, max_pages=1):
    results = True
    page = 1
    SHODAN_API_KEY = keys['keys']['shodan']
    pages = 0
    screenshot = ""
    logger.debug("Starting Shodan search worker for query=%s country=%s coordinates=%s", query, country, coordinates)

    while results:
        if pages == page:
            results = False
            break

        # Shodan sometimes fails with no reason, sleeping when it happens and it prevents rate limitation
        search = Search.objects.get(id=fk)
        api = Shodan(SHODAN_API_KEY)
        fail = False

        while not fail:
            try:
                sleep(3)
                if coordinates:
                    results = api.search("geo:" + coordinates + ",50 " + query, page)
                    fail = True
                elif country == "XX":
                    results = api.search(query, page)
                    fail = True
                else:
                    results = api.search("country:" + country + " " + query, page)
                    fail = True
            except Exception:
                fail = False
                logger.warning("Shodan search failed; sleeping before retry")

        try:
            total = results['total']

            if total == 0:
                logger.info("Shodan search returned no results for query=%s", query)
                break
        except Exception:
            logger.exception("Invalid Shodan response for query=%s", query)
            break

        pages = math.ceil(total / 100) + 1
        logger.debug("Shodan search query=%s total=%s pages=%s", query, total, pages)
        for counter, result in enumerate(results['matches']):
            lat = str(result['location']['latitude'])
            lon = str(result['location']['longitude'])
            city = ""
            indicator = []
            skip = False

            if 'honeypot' in result.get('tags', []):
                skip = True
```

```python
            if 'screenshot' in result:
                try:

                    screenshot = result['screenshot']['data']

                    with open("app_kamerka/static/images/screens/" + result['ip_str'] + ".jpg", "wb") as fh:
                        fh.write(base64.b64decode(screenshot))
                        fh.close()
                        for i in result['opts']['screenshot']['labels']:
                            indicator.append(i)
                except Exception as e:
                    pass
```

```python
            if not skip:
                device = Device(search=search, ip=result['ip_str'], product=product, org=result['org'],
                                data=result['data'], port=str(result['port']), type=search_type, city=city,
                                lat=lat, lon=lon,
                                country_code=result['location']['country_code'], query=search_type, category=category,
                                vulns=vulns, indicator=indicator, hostnames=hostnames, screenshot=screenshot)
                device.save()
```

---

## 2) Search page limits and max_pages behavior

Source:
- `kamerka/tasks.py`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/kamerka/tasks.py#L508-L569

Why it fits:
- This keeps Shodan searches bounded and safer for real-world use.
- It is a strong cherry-pick for forks that otherwise fetch too much data or burn credits quickly.
- It preserves the existing task flow while adding a simple control for page count.

Apply where:
- Your fork’s Shodan task scheduler for `shodan_search` plus any form field that controls `max_pages`.

```python
@shared_task(bind=True)
def shodan_search(self, fk, country=None, coordinates=None, ics=None, healthcare=None, coordinates_search=None,
                  all_results=False, infra=None, iot=False, max_pages=1):
    progress_recorder = ProgressRecorder(self)
    result = 0
    if country:
        total = len(ics)
        for c, i in enumerate(ics):
            if healthcare:
                if i in healthcare_queries:
                    try:
                        result += c
                        shodan_search_worker(country=country, fk=fk, query=healthcare_queries[i], search_type=i,
                                             category="healthcare",
                                             all_results=all_results, max_pages=max_pages)
                        progress_recorder.set_progress(c + 1, total=total)
                    except:
                        pass
```

```python
        page = page + 1
        if not all_results and page > max_pages:
            results = False
```

---

## 3) UI honeypot filter toggle

Source:
- `app_kamerka/templates/devices.html`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/app_kamerka/templates/devices.html#L86-L205

Why it fits:
- This is a lightweight UX improvement that makes noisy data easier to filter without major backend changes.
- It is especially useful if your fork still uses a DataTables table and repeated IP addresses are cluttering results.

Apply where:
- Your fork’s device list template that displays all devices or search results.

```html
<div class="panel-heading km-panel-heading-flex">
    <h3 class="panel-title">Devices</h3>
    <label class="km-filter-toggle" title="Hide IPs seen more than 3 times in the database">
        <input type="checkbox" id="ip-uniqueness-filter">
        <span class="km-toggle-track"><span class="km-toggle-thumb"></span></span>
        <span class="km-toggle-label">Filter Honeypots</span>
    </label>
</div>
```

```html
<script>
(function() {
    $.fn.dataTable.ext.search.push(function(settings, data, dataIndex) {
        if (!$('#ip-uniqueness-filter').is(':checked')) return true;
        var node = settings.aoData[dataIndex] && settings.aoData[dataIndex].nTr;
        if (!node) return true;
        return parseInt($(node).data('ip-count') || 0) <= 3;
    });
    $('#ip-uniqueness-filter').on('change', function() {
        $('.datatable').DataTable().draw();
    });
})();
</script>
```

---

## 4) Screenshot gallery with country filter + pagination

Source:
- `app_kamerka/views.py`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/app_kamerka/views.py#L460-L489
- `app_kamerka/templates/gallery.html`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/app_kamerka/templates/gallery.html#L59-L151

Why it fits:
- This is a practical feature for any fork that collects screenshots and needs to review them quickly.
- The view and template are small and mostly self-contained.
- It adds query filter and pagination without forcing a larger redesign.

Apply where:
- Your fork’s gallery view and template.

```python
def gallery(request):
    active_country = request.GET.get('country', '').strip().upper()
    page_size_options = [20, 50, 100]
    try:
        page_size = int(request.GET.get('per_page', page_size_options[0]))
    except (TypeError, ValueError):
        page_size = page_size_options[0]
    if page_size not in page_size_options:
        page_size = page_size_options[0]

    qs = Device.objects.filter(screenshot__gt='', screenshot__isnull=False).order_by('-id')
    if active_country:
        qs = qs.filter(country_code=active_country)
    countries = (Device.objects
                 .filter(screenshot__gt='', screenshot__isnull=False)
                 .exclude(country_code='')
                 .values_list('country_code', flat=True)
                 .distinct()
                 .order_by('country_code'))
    paginator = Paginator(qs, page_size)
    page_obj = paginator.get_page(request.GET.get('page', 1))
    context = {
        "devices": page_obj,
        "page_obj": page_obj,
        "countries": list(countries),
        "active_country": active_country,
        "page_size": page_size,
        "page_size_options": page_size_options,
    }
    return render(request, "gallery.html", context=context)
```

```html
<form method="get" action="{% url 'gallery' %}" style="display:flex;align-items:center;gap:6px;margin:0;">
    {% if active_country %}
    <input type="hidden" name="country" value="{{ active_country }}">
    {% endif %}
    <label for="gallery-per-page" style="font-family:'JetBrains Mono',monospace;font-size:10px;letter-spacing:0.1em;color:#5a7d8e;text-transform:uppercase;">
        Page size
    </label>
    <select id="gallery-per-page" name="per_page" onchange="this.form.submit()">
        {% for option in page_size_options %}
        <option value="{{ option }}" {% if page_size == option %}selected{% endif %}>{{ option }}</option>
        {% endfor %}
    </select>
</form>
```

---

## 5) Screenshot modal UX

Source:
- `app_kamerka/templates/device.html`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/app_kamerka/templates/device.html#L405-L419
- `app_kamerka/static/css/kamerka-ui.css`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/app_kamerka/static/css/kamerka-ui.css#L620-L721

Why it fits:
- This adds a straightforward review workflow: click screenshot, inspect full image, keep context.
- It improves the analyst workflow without scaffolding major changes.
- It is low-risk if your fork already stores screenshots as base64.

Apply where:
- Your fork’s device details page and the CSS file that styles screenshot cards.

```html
{% if device.screenshot %}
<div class="modal fade screenshot-modal" id="screenshot-modal" tabindex="-1" role="dialog" aria-labelledby="screenshot-modal-title" aria-hidden="true">
    <div class="modal-dialog screenshot-modal-dialog" role="document">
        <div class="modal-content screenshot-modal-content">
            <div class="modal-header screenshot-modal-header">
                <button type="button" class="close screenshot-modal-close" data-dismiss="modal" aria-label="Close">&times;</button>
                <h4 class="modal-title" id="screenshot-modal-title">Screenshot</h4>
            </div>
            <div class="modal-body screenshot-modal-body">
                <img class="screenshot-modal-image" src="data:image/jpeg;base64,{{ device.screenshot }}" alt="Device screenshot enlarged">
            </div>
        </div>
    </div>
</div>
{% endif %}
```

```css
.screenshot-modal {
  text-align: center;
}

.screenshot-modal::before {
  content: '';
  display: inline-block;
  height: 100%;
  vertical-align: middle;
}

.screenshot-modal-dialog {
  display: inline-block;
  margin: 0 auto;
  max-width: min(1180px, 92vw);
  text-align: left;
  vertical-align: middle;
  width: auto;
}

.screenshot-modal-content {
  background:
    radial-gradient(circle at 92% 0, rgba(0, 212, 240, 0.10), transparent 32%),
    rgba(4, 10, 20, 0.96);
  border: 1px solid var(--km-border-strong);
  border-radius: var(--km-radius);
  box-shadow: 0 24px 80px rgba(0, 0, 0, 0.78), 0 0 34px rgba(0, 212, 240, 0.18);
}
```

---

## 6) Security hygiene: gitignore

Source:
- `.gitignore`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/.gitignore#L1-L55

Why it fits:
- This is the safest upstream idea to adopt.
- It reduces the chance of secrets, local DB files, generated screenshots, and editor artifacts being checked into the repository.
- It has almost no risk and very high value.

Apply where:
- Your repo root `.gitignore`.

```gitignore
# API keys and secrets
keys.json

# Database
db.sqlite3
*.sqlite3

# Redis dump
dump.rdb

# Screenshot images (collected at runtime)
app_kamerka/static/images/screens/

# Django migrations (auto-generated)
app_kamerka/migrations/

# Python
__pycache__/
*.py[cod]
*.pyo
*.pyd
*.egg-info/
*.egg
dist/
build/
.eggs/

# Virtual environment
.venv/
venv/
env/
ENV/

# IDE
.idea/
.vscode/
*.iml

# macOS
.DS_Store
.AppleDouble
.LSOverride

# Logs
*.log
celerybeat-schedule
celerybeat.pid

# Coverage
.coverage
htmlcov/

# Claude Code session data
.claude/
```

---

## 7) Dependency modernization reference

Source:
- `requirements.txt`
- https://github.com/woj-ciech/Kamerka-GUI/blob/7312013e8a2d78f20c22e14e603d2afbd355b972/requirements.txt#L1-L15

Why it fits:
- This is a reference list for modernizing the stack without taking on unrelated features.
- It is useful if the fork is based on older Django/Celery versions and only needs a compatibility upgrade.

Apply where:
- Your repo root `requirements.txt`.

```pip requirements
# Python 3.10+ is required by the maintained Django/requests/redis stack.
Django>=5.2,<5.3
celery==5.6.3
celery-progress==0.5
redis==6.4.0
requests==2.34.2
flickrapi==2.4.0
pycountry==26.2.16
shodan==1.31.0
beautifulsoup4==4.14.3
pynmea2==1.19.0
maxminddb==3.1.1
xmltodict==1.0.4
python-libnmap==0.7.3
lxml==6.1.1
```

---

## Recommended merge order

1. `.gitignore`
2. `shodan_search_worker` honeypot filtering
3. `max_pages` / bounded search behavior
4. screenshot gallery + country filter
5. screenshot modal UI
6. dependency refresh

This avoids the risk of large structural merges while still backporting the most useful behavior.

---

## Notes for your fork

Most of the upstream repo’s best value is in:
- search noise reduction
- screenshot workflows
- result cleanup
- environment hygiene

The least valuable wholesale imports are:
- full UI redesigns
- broad architectural refactors
- feature removals or replacement of your fork’s custom direction

If you want, the next logical step is:
- port the exact `shodan_search_worker` snippet into your fork
- add the honeypot toggle to your devices/results templates
- add `.gitignore` safety rules
- then revisit screenshot gallery and modal behavior after the backend is stable
