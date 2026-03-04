# Earth surface texture cache

This directory stores the Earth surface texture used by the 3-D globe widget
for **offline-first** rendering.

## How the texture is populated

On the first run `globe_3d.globe_widget` calls
`pyvista.examples.planets.download_earth_surface()` which downloads a high-res
JPEG from the PyVista asset server and caches it locally at:

    assets/earth_surface.jpg

Subsequent runs load the texture directly from this file without any network
access.

## Manual population

If the operator works in an air-gapped environment, copy any
`2048×1024` (or higher) equirectangular Earth texture JPEG here and name it
`earth_surface.jpg`.  Free sources:

* NASA Blue Marble: https://visibleearth.nasa.gov/images/73909
* Natural Earth II:  https://www.naturalearthdata.com/downloads/10m-raster-data/10m-natural-earth-2/

## Gitignore

`earth_surface.jpg` is excluded from version control (see `.gitignore`) because
it is a large binary asset (≥ 5 MB) that should be downloaded or provided
separately.
