import sys

if "--gui" in sys.argv:
    from .gui import run_gui
    run_gui()
else:
    from .cli import main
    main()
