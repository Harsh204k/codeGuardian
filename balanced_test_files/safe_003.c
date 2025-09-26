static void fd_init(FDrive *drv)
{
    /* Drive */
    drv->drive = FDRIVE_DRV_NONE;
    drv->perpendicular = 0;
    /* Disk */
    drv->last_sect = 0;
    drv->max_track = 0;
}