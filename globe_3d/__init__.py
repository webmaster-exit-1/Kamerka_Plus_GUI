"""
globe_3d – Local-first 3D rendering engine for Kamerka-Plus-GUI.

Modules
-------
coordinate_mapper   WGS-84 (lat/lon) → Cartesian (X, Y, Z) using spherical
                    trigonometry; radius is kept in sync with the PyVista Earth
                    sphere so spikes are placed exactly on the surface.
globe_widget        PyVista + PyQt6 QtInteractor that renders the textured Earth
                    mesh and routes picker events to the GUI's Details panel.
spike_renderer      Creates 3-D cylinder ("spike") meshes coloured by Nuclei
                    severity and scaled in height by device-cluster density.
lod_manager         Level-of-Detail helper: aggregates devices into clusters for
                    the global view and dissolves them back to individual points
                    as the camera zooms in.
"""
