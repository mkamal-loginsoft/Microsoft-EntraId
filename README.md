to run the app
hypercorn -w 8 -b 0.0.0.0:5000 main:app
