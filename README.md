# Cisco 펌웨어 모니터

Cisco 공식 릴리스 노트를 읽어 Nexus 9000 NX-OS, Catalyst 9300 IOS XE, UCS C-Series 독립형 펌웨어를 살펴보는 FastAPI 초안입니다.

## 실행

Python 3.10 이상을 사용합니다.

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m uvicorn firmware.main:app
```

브라우저에서 `http://127.0.0.1:8000/`를 엽니다. API는 `/docs`에 있습니다. 시작 시 첫 수집을 하고 이후 기본 1시간마다 확인합니다. `FIRMWARE_POLL_SECONDS`로 주기를 바꾸거나 `0`으로 설정해 **지금 확인** 버튼으로만 수집할 수 있습니다.

- 첫 수집은 기준선을 만듭니다. 이후 새 버전과 기존 문서의 내용 개정을 화면에 표시합니다.
- 기준·목표 버전을 입력하면 수집한 릴리스 노트의 추가·삭제 항목과 출처를 보여줍니다. 아직 수집하지 않은 버전은 Cisco 목록에서 해당 문서를 조회합니다.
- 조치 권고는 릴리스 노트의 텍스트 규칙으로 생성합니다. 증거가 부족하면 보류하며, 근거 문구와 원문을 함께 표시합니다. 현재 보안 공지 별도 연동과 보유 장비 판정은 후속 범위입니다.

## 업데이트 전 확인

- Nexus 9000과 Catalyst 9300의 Cisco 권장 릴리스 표를 조회합니다. 기준·목표 버전이 표에 있으면 강조하고, 표의 모델과 지원 조건을 함께 제공합니다.
- 대상 릴리스 노트의 CVE를 Cisco의 공개 PSIRT 피드와 대조하고, 직접 링크가 있으면 공지도 확인합니다. 화면에는 공식 심각도와 출처를 표시합니다. 이 범위는 Cisco 보안 공지 전체에 대한 영향 판정을 포함하지 않습니다.
- 공식 가이드에서 확인한 재부팅과 설치 방식, 목표 릴리스 노트에서 추출한 관련 문구를 제공합니다. 실제 장비 모델, 부품, 업그레이드 경로와 운영 영향은 검토 시 확인해야 합니다.

## Groq 비교 요약

프로젝트 루트의 `.env`에 `GROQ_API_KEY` 또는 `groq_api_key`를 설정합니다. 화면에서 두 버전을 비교하면 공개 릴리스 노트의 차이를 바탕으로 핵심 요약과 항목별 Cisco 근거 링크를 표시합니다. 원문 차이는 화면에서 펼쳐 볼 수 있습니다. 기본 모델은 `openai/gpt-oss-20b`이며 `GROQ_MODEL`로 변경할 수 있습니다.

API에서도 `/api/{family}/compare`에 `summarize=true`를 지정할 수 있습니다. AI에는 목표 쪽에서 확인된 차이 항목을 최대 24개 전달하고, 같은 입력의 성공 응답은 프로세스 메모리에 저장합니다. Groq 호출에 실패해도 원문 비교 결과는 제공됩니다.

## 저장 및 테스트

기본 저장소는 메모리입니다. 프로세스를 다시 시작하면 첫 수집부터 시작합니다. 실행은 단일 Uvicorn 워커를 전제로 합니다.

```sh
python -m unittest discover -s tests -v
FIRMWARE_DATABASE_URL=sqlite:///firmware.sqlite3 python -m uvicorn firmware.main:app
```

테스트는 임시 SQLite 파일과 모의 Cisco 응답을 사용합니다. 저장 코드는 SQLAlchemy의 JSON과 일반 SQL을 사용합니다. 최종 DB는 MySQL을 가정하며, 전환 시 PyMySQL을 설치하고 `mysql+pymysql://사용자:비밀번호@호스트/DB이름?charset=utf8mb4` 형식의 URL을 설정합니다. MySQL 실서버 연결 검증은 후속 작업입니다.

장비군별 최대 12개 문서를 주기적으로 재확인합니다. 비교 결과의 중간 버전 목록은 수집 범위를 따르므로 전체 업그레이드 경로는 Cisco 원문에서 확인할 수 있습니다.
