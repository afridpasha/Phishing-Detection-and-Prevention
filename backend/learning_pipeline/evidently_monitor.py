def check_model_drift(reference_data, current_data) -> dict:
    try:
        from evidently.metric_preset import ClassificationPreset, DataDriftPreset
        from evidently.report import Report

        report = Report(metrics=[DataDriftPreset(), ClassificationPreset()])
        report.run(reference_data=reference_data, current_data=current_data)
        result = report.as_dict()
        return {'drift_detected': True, 'report': result}
    except Exception:
        return {'drift_detected': False, 'report': {}}
