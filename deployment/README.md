# CodeGuardian Docker Deployment

This directory contains all the necessary files for deploying CodeGuardian using Docker and Docker Compose.

## Quick Start

1. **Setup Environment Variables**
   ```bash
   cp .env.template .env
   # Edit .env file with your configuration
   ```

2. **Build and Start Services**
   ```bash
   # Start core services (app, database, cache)
   docker-compose up -d

   # Or start with specific profiles
   docker-compose --profile web --profile monitoring up -d
   ```

3. **Initialize Database**
   ```bash
   # Database will be automatically initialized with init-db.sql
   # Check logs to ensure successful setup
   docker-compose logs postgres
   ```

4. **Access Services**
   - Main API: http://localhost:8000
   - Web UI: http://localhost:5000
   - Grafana: http://localhost:3000
   - Prometheus: http://localhost:9090

## Service Profiles

The Docker Compose configuration uses profiles to organize services:

- **Default**: Core services (codeguardian, postgres, redis)
- **web**: Web UI service
- **worker**: Background processing workers
- **training**: ML model training service
- **proxy**: Nginx reverse proxy
- **monitoring**: Prometheus and Grafana

## Available Services

### Core Services
- **codeguardian**: Main application API
- **postgres**: PostgreSQL database
- **redis**: Redis cache and session store

### Optional Services
- **web-ui**: Flask/Django web interface
- **worker**: Celery background workers
- **ml-trainer**: ML model training service
- **nginx**: Reverse proxy with SSL
- **prometheus**: Metrics collection
- **grafana**: Monitoring dashboards

## Commands

### Basic Operations
```bash
# Start all services
docker-compose up -d

# Start with specific profiles
docker-compose --profile web --profile monitoring up -d

# View logs
docker-compose logs -f codeguardian

# Stop services
docker-compose down

# Stop and remove volumes
docker-compose down -v
```

### Development
```bash
# Build development image
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d

# Run tests
docker-compose exec codeguardian python -m pytest

# Access shell in container
docker-compose exec codeguardian bash
```

### ML Model Training
```bash
# Train models (one-time)
docker-compose --profile training up ml-trainer

# Check training logs
docker-compose logs ml-trainer
```

### Monitoring
```bash
# Start monitoring stack
docker-compose --profile monitoring up -d prometheus grafana

# View metrics
curl http://localhost:9090/metrics
```

## Configuration

### Environment Variables
Key variables in `.env`:
- `POSTGRES_PASSWORD`: Database password
- `REDIS_PASSWORD`: Redis password
- `GRAFANA_PASSWORD`: Grafana admin password
- `FLASK_ENV`: Application environment (development/production)

### SSL/TLS Setup
For production with HTTPS:
1. Place SSL certificates in `ssl/` directory:
   - `cert.pem`: SSL certificate
   - `key.pem`: Private key
2. Start with proxy profile: `docker-compose --profile proxy up -d`

### Custom Configuration
- **nginx.conf**: Reverse proxy configuration
- **prometheus.yml**: Metrics collection setup
- **init-db.sql**: Database initialization

## Data Persistence

Persistent volumes:
- `postgres_data`: Database files
- `redis_data`: Redis persistence
- `scan_results`: Vulnerability scan results
- `model_cache`: ML model cache
- `prometheus_data`: Metrics data
- `grafana_data`: Dashboard configurations

## Scaling

### Horizontal Scaling
```bash
# Scale API instances
docker-compose up -d --scale codeguardian=3

# Scale workers
docker-compose --profile worker up -d --scale worker=5
```

### Resource Limits
Add resource limits in docker-compose.yml:
```yaml
services:
  codeguardian:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 4G
        reservations:
          cpus: '1.0'
          memory: 2G
```

## Troubleshooting

### Common Issues

1. **Port Conflicts**
   ```bash
   # Check port usage
   netstat -tulpn | grep :8000
   
   # Change ports in docker-compose.yml if needed
   ```

2. **Database Connection Issues**
   ```bash
   # Check database logs
   docker-compose logs postgres
   
   # Test connection
   docker-compose exec postgres psql -U codeguardian -d codeguardian
   ```

3. **Memory Issues**
   ```bash
   # Check container resource usage
   docker stats
   
   # Increase memory limits or add swap
   ```

4. **SSL Certificate Issues**
   ```bash
   # Generate self-signed certificates for testing
   mkdir -p ssl
   openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
     -keyout ssl/key.pem -out ssl/cert.pem
   ```

### Logs and Debugging
```bash
# View all logs
docker-compose logs

# Follow specific service logs
docker-compose logs -f codeguardian

# Debug container
docker-compose exec codeguardian bash
docker-compose run --rm codeguardian python -c "import sys; print(sys.version)"
```

## Security Considerations

1. **Change Default Passwords**: Update all passwords in `.env`
2. **Network Security**: Use custom networks and firewall rules
3. **SSL/TLS**: Enable HTTPS in production
4. **Access Control**: Implement proper authentication
5. **Updates**: Regularly update container images
6. **Secrets Management**: Use Docker secrets or external vault

## Production Deployment

For production environments:

1. **Use Production Profile**
   ```bash
   FLASK_ENV=production docker-compose --profile web --profile proxy --profile monitoring up -d
   ```

2. **Enable SSL**
   - Configure valid SSL certificates
   - Update nginx.conf with your domain

3. **Database Security**
   - Use strong passwords
   - Enable SSL for database connections
   - Regular backups

4. **Monitoring**
   - Set up alerting rules
   - Configure log aggregation
   - Monitor resource usage

5. **Backup Strategy**
   - Database backups: `docker-compose exec postgres pg_dump...`
   - Volume backups: `docker run --rm -v postgres_data:/data -v $(pwd):/backup alpine tar czf /backup/postgres-backup.tar.gz /data`

## Support

For issues or questions:
1. Check logs: `docker-compose logs`
2. Review configuration files
3. Verify environment variables
4. Check network connectivity
5. Consult application documentation