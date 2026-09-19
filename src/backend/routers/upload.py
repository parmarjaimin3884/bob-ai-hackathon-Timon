"""
Upload router for Threat Intelligence alerts.
Handles multipart CSV uploads, performs file-level validation, and stores files safely.
"""

import ipaddress
import logging
import socket
import uuid
from pathlib import Path
from urllib.parse import urlparse
import httpx
from fastapi import APIRouter, BackgroundTasks, Depends, File, UploadFile, status
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

try:
    from database.session import get_db
    from database.models import Alert as AlertDB, UserDB
    from schemas.upload import UploadResponse, ErrorResponse, IngestResponse, URLIngestRequest
    from services.file_storage import FileStorageService, StorageValidationError, BASE_DIR
    from services.csv_parser import CSVParser, CSVParserError
    from services.json_parser import JSONAlertParser, JSONParserError
    from repositories.alert_repository import AlertRepository
    from routers.auth import get_current_user_obj
except ImportError:
    from backend.database.session import get_db
    from backend.database.models import Alert as AlertDB, UserDB
    from backend.schemas.upload import UploadResponse, ErrorResponse, IngestResponse, URLIngestRequest
    from backend.services.file_storage import FileStorageService, StorageValidationError, BASE_DIR
    from backend.services.csv_parser import CSVParser, CSVParserError
    from backend.services.json_parser import JSONAlertParser, JSONParserError
    from backend.repositories.alert_repository import AlertRepository
    from backend.routers.auth import get_current_user_obj

logger = logging.getLogger(__name__)

router = APIRouter(
    prefix="/api/v1",
    tags=["Alert Upload & Ingestion"],
)

storage_service = FileStorageService()
csv_parser = CSVParser()
json_parser = JSONAlertParser()
MAX_API_RESPONSE_BYTES = 5 * 1024 * 1024


@router.post(
    "/upload",
    response_model=UploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload Raw Alerts CSV",
    description=(
        "Accepts a raw security alert CSV file via multipart/form-data and stores it on the server.\n\n"
        "**Validation Rules:**\n"
        "- File must be provided.\n"
        "- File extension must strictly be `.csv`.\n"
        "- File content must not be empty (0 bytes).\n"
        "- Other file formats (.txt, .pdf, .xlsx, .json) are rejected with 400 Bad Request.\n\n"
        "*Note: This endpoint performs storage and file-level integrity checks only; "
        "parsing and threat correlation occur in subsequent pipeline stages.*"
    ),
    responses={
        201: {
            "description": "File successfully uploaded and stored",
            "model": UploadResponse,
            "content": {
                "application/json": {
                    "example": {
                        "success": True,
                        "message": "File uploaded successfully",
                        "file_name": "alerts_20260913_153001.csv",
                        "file_path": "uploads/alerts_20260913_153001.csv",
                    }
                }
            },
        },
        400: {
            "description": "Validation failed (invalid file type, empty file, or missing file)",
            "model": ErrorResponse,
            "content": {
                "application/json": {
                    "examples": {
                        "invalid_extension": {
                            "summary": "Non-CSV file uploaded",
                            "value": {
                                "success": False,
                                "message": "Only CSV files are allowed",
                            },
                        },
                        "empty_file": {
                            "summary": "Empty file uploaded",
                            "value": {
                                "success": False,
                                "message": "Uploaded file is empty",
                            },
                        },
                    }
                }
            },
        },
        500: {
            "description": "Internal server or disk error during upload processing",
            "model": ErrorResponse,
            "content": {
                "application/json": {
                    "example": {
                        "success": False,
                        "message": "An unexpected error occurred while saving the file",
                    }
                }
            },
        },
    },
)
async def upload_alerts_csv(
    file: UploadFile = File(
        ...,
        description="CSV file containing raw security alerts (e.g. SIEM, satellite, sensor logs)",
    ),
):
    """
    Handle CSV upload: validates file integrity, extension, and delegates persistence to FileStorageService.
    """
    logger.info("Upload request received")

    # Guard: Missing file object or filename
    if not file or not file.filename:
        logger.warning("Upload failed: No file was attached to the request")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                success=False,
                message="Only CSV files are allowed",
            ).model_dump(),
        )

    try:
        file_name, file_path = await storage_service.save_file(file)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=UploadResponse(
                success=True,
                message="File uploaded successfully",
                file_name=file_name,
                file_path=file_path,
            ).model_dump(),
        )

    except StorageValidationError as val_err:
        logger.warning(f"Validation failure during upload: {val_err.message}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                success=False,
                message=val_err.message,
            ).model_dump(),
        )

    except Exception as exc:
        logger.error(f"Unexpected error during upload processing: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(
                success=False,
                message="An unexpected error occurred while saving the file",
            ).model_dump(),
        )


def _bg_qdrant_sync(user_id: uuid.UUID) -> None:
    """Background task to synchronize newly correlated threat intelligence into Qdrant vector index."""
    try:
        try:
            from database.session import SessionLocal
            from services.qdrant_service import QdrantService
        except ImportError:
            from backend.database.session import SessionLocal
            from backend.services.qdrant_service import QdrantService

        with SessionLocal() as bg_db:
            q_svc = QdrantService.get_instance()
            q_svc.sync_from_database(db=bg_db, user_id=user_id)
        logger.info(f"Background Qdrant vector sync completed successfully for user {user_id}")
    except Exception as q_err:
        logger.warning(f"Background Qdrant vector sync warning: {q_err}")


async def _ingest_normalized_alerts(
    parsed_alerts, source_type: str, file_name: str, file_path: str, current_user: UserDB,
    db: Session, background_tasks: BackgroundTasks,
):
    """The single persistence and downstream-processing path for every ingestion source."""
    alert_repo = AlertRepository(db)
    upload_rec = alert_repo.create_upload(file_name=file_name, file_path=file_path, user_id=current_user.id)
    orm_alerts = []
    for a in parsed_alerts:
        sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
        orm_alerts.append(AlertDB(
            id=uuid.uuid4(), user_id=current_user.id, upload_id=upload_rec.id,
            timestamp=a.timestamp, src_ip=a.src_ip, dst_ip=a.dst_ip, event=a.event,
            severity=sev, source_type=source_type,
        ))
    count = alert_repo.bulk_insert_alerts(upload_id=upload_rec.id, alerts=orm_alerts, user_id=current_user.id)
    chains_count = mitre_count = scored_count = 0
    try:
        from services.alert_correlation import AlertCorrelationEngine
        from services.mitre_mapping import MitreMappingService
        from services.risk_scoring import RiskScoringEngine
        corr_result = AlertCorrelationEngine(db=db).correlate(user_id=current_user.id, persist=True)
        chains_count = len(corr_result.chains)
        mitre_count = MitreMappingService(db=db).map_all_chains(user_id=current_user.id).total_techniques
        scored_count = len(RiskScoringEngine(db=db).score_all_chains(user_id=current_user.id))
        background_tasks.add_task(_bg_qdrant_sync, current_user.id)
    except Exception as pipe_err:
        logger.warning("Correlation pipeline post-ingest warning: %s", pipe_err)
    try:
        from services.cache_service import cache
        for key in ("dashboard_stats", "analytics_overview", "all_attack_chains"):
            cache.delete(f"{key}_{current_user.id}")
    except Exception:
        pass
    return IngestResponse(
        success=True, message=f"Successfully ingested {count} alerts and correlated {chains_count} attack chains",
        upload_id=str(upload_rec.id), file_name=file_name, alerts_ingested=count,
        chains_correlated=chains_count, mitre_mapped=mitre_count, risk_scored=scored_count,
        source_type=source_type,
    )


def _validate_external_url(url: str) -> None:
    """Resolve and reject non-public targets before making an outbound request (SSRF guard)."""
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("Invalid URL")
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or (443 if parsed.scheme == "https" else 80), type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("Unable to resolve API host") from exc
    for address in addresses:
        if not ipaddress.ip_address(address[4][0]).is_global:
            raise ValueError("API URL must resolve to a public address")


@router.post(
    "/upload/ingest",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload, Parse and Ingest Alerts CSV into Database",
    description=(
        "Accepts a raw security alert CSV file, verifies formatting, saves file to disk, "
        "parses alerts via CSVParser, and bulk inserts them into PostgreSQL alerts table."
    ),
)
async def upload_and_ingest_alerts(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="CSV file with columns: timestamp, src_ip, dst_ip, event, severity"),
    current_user: UserDB = Depends(get_current_user_obj),
    db: Session = Depends(get_db),
):
    """
    End-to-end ingestion scoped to the authenticated user:
    1. Disk storage
    2. CSV parsing and validation
    3. PostgreSQL storage in uploads and alerts tables with user_id
    4. Auto-correlate, MITRE map, and risk score for this user's data
    """
    if not file or not file.filename:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(
                success=False,
                message="Only CSV files are allowed",
            ).model_dump(),
        )

    try:
        # 1. Save file to disk
        file_name, file_path = await storage_service.save_file(file)

        # 2. Read saved file content and parse
        full_path = BASE_DIR / file_path
        with open(full_path, "r", encoding="utf-8") as f:
            parse_result = csv_parser.parse(f)

        parsed_alerts = parse_result.get("alerts", [])
        if not parsed_alerts:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content=ErrorResponse(
                    success=False,
                    message="CSV contains no valid alert rows",
                ).model_dump(),
            )

        response = await _ingest_normalized_alerts(
            parsed_alerts, "csv", file_name, file_path, current_user, db, background_tasks
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=response.model_dump())

        # 3. Create upload record in DB with user_id
        alert_repo = AlertRepository(db)
        upload_rec = alert_repo.create_upload(
            file_name=file_name,
            file_path=file_path,
            user_id=current_user.id,
        )

        # 4. Convert schemas.alert.Alert to database.models.Alert with user_id
        orm_alerts = []
        for a in parsed_alerts:
            sev = a.severity.value if hasattr(a.severity, "value") else str(a.severity)
            orm_alerts.append(
                AlertDB(
                    id=uuid.uuid4(),
                    user_id=current_user.id,
                    upload_id=upload_rec.id,
                    timestamp=a.timestamp,
                    src_ip=a.src_ip,
                    dst_ip=a.dst_ip,
                    event=a.event,
                    severity=sev,
                )
            )

        # 5. Bulk insert alerts with user_id
        count = alert_repo.bulk_insert_alerts(
            upload_id=upload_rec.id,
            alerts=orm_alerts,
            user_id=current_user.id,
        )
        logger.info("Successfully ingested %d alerts for user %s from file %s", count, current_user.id, file_name)

        # 6. Trigger automated correlation, MITRE mapping, and risk scoring pipeline scoped to current_user
        chains_count = 0
        mitre_count = 0
        scored_count = 0
        try:
            from services.alert_correlation import AlertCorrelationEngine
            from services.mitre_mapping import MitreMappingService
            from services.behavioral_analysis import BehavioralAnalysisEngine
            from services.risk_scoring import RiskScoringEngine

            corr_engine = AlertCorrelationEngine(db=db)
            corr_result = corr_engine.correlate(user_id=current_user.id, persist=True)
            chains_count = len(corr_result.chains)

            mitre_service = MitreMappingService(db=db)
            mitre_res = mitre_service.map_all_chains(user_id=current_user.id)
            mitre_count = mitre_res.total_techniques

            # Run behavioral anomaly analysis on all chains before risk scoring
            behavioral_engine = BehavioralAnalysisEngine(db=db)
            behavioral_engine.analyze_all_chains(user_id=current_user.id, persist=True)

            risk_engine = RiskScoringEngine(db=db)
            risk_scores = risk_engine.score_all_chains(user_id=current_user.id)
            scored_count = len(risk_scores)

            logger.info(
                f"Auto-pipeline executed for user {current_user.id}: {chains_count} chains correlated, "
                f"{mitre_count} MITRE techniques mapped, behavioral analysis performed, {scored_count} risk-scored"
            )

            # Auto-sync newly correlated threat intelligence into Qdrant vector index in the background
            if background_tasks:
                background_tasks.add_task(_bg_qdrant_sync, current_user.id)
            else:
                _bg_qdrant_sync(current_user.id)
        except Exception as pipe_err:
            logger.warning(f"Correlation pipeline post-ingest warning: {pipe_err}")

        # Start background cache pre-warming so the dashboard loads instantly
        def _bg_prewarm_cache(uid):
            try:
                from database.session import SessionLocal
                from routers.dashboard import get_dashboard_stats, get_analytics_overview
                from routers.correlation import get_attack_chains
                from services.cache_service import cache
                
                class DummyUser:
                    id = uid
                    
                user_obj = DummyUser()
                with SessionLocal() as db_session:
                    # Clear out the old cached data
                    cache.delete(f"dashboard_stats_{uid}")
                    cache.delete(f"analytics_overview_{uid}")
                    cache.delete(f"all_attack_chains_{uid}")
                    
                    # Re-execute heavy aggregations in the background to pre-warm the cache
                    get_dashboard_stats(current_user=user_obj, db=db_session)
                    get_analytics_overview(current_user=user_obj, db=db_session)
                    get_attack_chains(current_user=user_obj, db=db_session)
            except Exception as e:
                logger.warning(f"Cache pre-warm failed for {uid}: {e}")

        if background_tasks:
            background_tasks.add_task(_bg_prewarm_cache, current_user.id)
        else:
            _bg_prewarm_cache(current_user.id)

        return JSONResponse(
            status_code=status.HTTP_201_CREATED,
            content=IngestResponse(
                success=True,
                message=f"Successfully ingested {count} alerts and correlated {chains_count} attack chains",
                upload_id=str(upload_rec.id),
                file_name=file_name,
                alerts_ingested=count,
                chains_correlated=chains_count,
                mitre_mapped=mitre_count,
                risk_scored=scored_count,
            ).model_dump(),
        )

    except StorageValidationError as val_err:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(success=False, message=val_err.message).model_dump(),
        )
    except CSVParserError as parse_err:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(success=False, message=str(parse_err)).model_dump(),
        )
    except Exception as exc:
        logger.error(f"Error during alert ingestion: {exc}", exc_info=True)
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content=ErrorResponse(success=False, message=f"Ingestion failed: {str(exc)}").model_dump(),
        )


@router.post("/upload-json", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def upload_and_ingest_alerts_json(
    background_tasks: BackgroundTasks,
    file: UploadFile = File(..., description="JSON alert array or {alerts: [...]} wrapper"),
    current_user: UserDB = Depends(get_current_user_obj),
    db: Session = Depends(get_db),
):
    """Upload JSON, normalize it to canonical Alert records, and use the CSV pipeline's persistence path."""
    try:
        file_name, file_path = await storage_service.save_json_file(file)
        raw = (BASE_DIR / file_path).read_bytes()
        result = json_parser.parse_bytes(raw, source_type="json")
        response = await _ingest_normalized_alerts(
            result["alerts"], "json", file_name, file_path, current_user, db, background_tasks
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=response.model_dump())
    except (StorageValidationError, JSONParserError) as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=ErrorResponse(success=False, message=str(exc)).model_dump())
    except Exception as exc:
        logger.error("JSON ingestion failed", exc_info=True)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=ErrorResponse(success=False, message="JSON ingestion failed").model_dump())


@router.post("/ingest-url", response_model=IngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_alerts_url(
    request: URLIngestRequest,
    background_tasks: BackgroundTasks,
    current_user: UserDB = Depends(get_current_user_obj),
    db: Session = Depends(get_db),
):
    """Safely fetch a public JSON feed and send its normalized alerts through the shared pipeline."""
    try:
        _validate_external_url(request.url)
        # Header support is intentionally limited; callers cannot alter routing or request framing.
        headers = {k: v for k, v in (request.headers or {}).items() if k.lower() not in {"host", "content-length", "transfer-encoding"}}
        async with httpx.AsyncClient(timeout=httpx.Timeout(10.0), follow_redirects=False) as client:
            async with client.stream("GET", request.url, headers=headers) as upstream:
                if 300 <= upstream.status_code < 400:
                    raise JSONParserError("API redirects are not allowed")
                if upstream.status_code >= 400:
                    raise JSONParserError(f"API returned HTTP {upstream.status_code}")
                size_header = upstream.headers.get("content-length")
                if size_header and int(size_header) > MAX_API_RESPONSE_BYTES:
                    raise JSONParserError("API response is too large")
                chunks, total = [], 0
                async for chunk in upstream.aiter_bytes():
                    total += len(chunk)
                    if total > MAX_API_RESPONSE_BYTES:
                        raise JSONParserError("API response is too large")
                    chunks.append(chunk)
        result = json_parser.parse_bytes(b"".join(chunks), source_type="api")
        generated_name = f"api_{uuid.uuid4().hex[:12]}.json"
        response = await _ingest_normalized_alerts(
            result["alerts"], "api", generated_name, request.url, current_user, db, background_tasks
        )
        return JSONResponse(status_code=status.HTTP_201_CREATED, content=response.model_dump())
    except ValueError as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=ErrorResponse(success=False, message=str(exc)).model_dump())
    except (httpx.TimeoutException, httpx.NetworkError):
        return JSONResponse(status_code=status.HTTP_502_BAD_GATEWAY, content=ErrorResponse(success=False, message="Unable to connect to API").model_dump())
    except JSONParserError as exc:
        return JSONResponse(status_code=status.HTTP_400_BAD_REQUEST, content=ErrorResponse(success=False, message=str(exc)).model_dump())
    except Exception:
        logger.error("URL ingestion failed", exc_info=True)
        return JSONResponse(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, content=ErrorResponse(success=False, message="API ingestion failed").model_dump())


@router.post(
    "/demo/start-simulation",
    response_model=IngestResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Start Live Simulation Ingestion",
    description="Loads enterprise alert feed, correlates attack chains, maps MITRE tactics, analyzes behavioral anomalies, and scores risks in real time.",
)
async def start_demo_simulation(
    background_tasks: BackgroundTasks,
    limit: int = 300,
    current_user: UserDB = Depends(get_current_user_obj),
    db: Session = Depends(get_db),
):
    """Run one-click live simulation with real enterprise threat alerts."""
    sample_csv_path = Path(__file__).resolve().parent.parent / "sample_data" / "enterprise_threat_alerts_1000.csv"
    if not sample_csv_path.exists():
        sample_csv_path = Path(__file__).resolve().parent.parent / "sample_data" / "realworld_threat_alerts_1000.csv"

    if not sample_csv_path.exists():
        return JSONResponse(
            status_code=status.HTTP_404_NOT_FOUND,
            content=ErrorResponse(success=False, message="Sample alert dataset not found").model_dump(),
        )

    with open(sample_csv_path, "r", encoding="utf-8") as f:
        parse_result = csv_parser.parse(f)

    parsed_alerts = parse_result.get("alerts", [])[:limit]
    if not parsed_alerts:
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content=ErrorResponse(success=False, message="No alerts found in dataset").model_dump(),
        )

    generated_name = f"simulated_enterprise_feed_{limit}.csv"
    file_path = f"uploads/{generated_name}"

    response = await _ingest_normalized_alerts(
        parsed_alerts, "simulation", generated_name, file_path, current_user, db, background_tasks
    )
    return JSONResponse(status_code=status.HTTP_201_CREATED, content=response.model_dump())


