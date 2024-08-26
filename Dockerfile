# Creator: GHOST <https://github.com/GHOSTsama2503>
FROM python:3.12.5-slim

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
 
WORKDIR /src

CMD [ "python3", "app.py" ]
