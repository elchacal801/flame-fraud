/**
 * flame-data.js - FLAME Data Loader
 *
 * Fetches and caches the flame-data.json file.
 * Provides the data to app.js for rendering.
 */

const FlameData = (function () {
    let _data = null;
    let _loading = false;
    let _callbacks = [];

    const DATA_URL = 'database/flame-data.json';

    async function load() {
        if (_data) return _data;
        if (_loading) {
            return new Promise((resolve, reject) => {
                _callbacks.push({ resolve, reject });
            });
        }

        _loading = true;

        try {
            const response = await fetch(DATA_URL);
            if (!response.ok) {
                throw new Error('Failed to load data: ' + response.status + ' ' + response.statusText);
            }
            _data = await response.json();
            _loading = false;
            _callbacks.forEach(cb => cb.resolve(_data));
            _callbacks = [];
            return _data;
        } catch (err) {
            _loading = false;
            _callbacks.forEach(cb => cb.reject(err));
            _callbacks = [];
            throw err;
        }
    }

    function getData() {
        return _data;
    }

    /**
     * Extract unique values for a given field across all submissions.
     */
    function getUniqueValues(field) {
        if (!_data) return [];
        const values = new Set();
        _data.forEach(item => {
            const val = item[field];
            if (Array.isArray(val)) {
                val.forEach(v => values.add(v));
            } else if (val) {
                values.add(val);
            }
        });
        return Array.from(values).sort();
    }

    /**
     * Get aggregate stats from the loaded data.
     */
    function getStats() {
        if (!_data) return { total: 0, fraudTypes: 0, sectors: 0 };
        return {
            total: _data.length,
            fraudTypes: getUniqueValues('fraud_types').length,
            sectors: getUniqueValues('sectors').length,
        };
    }

    return {
        load,
        getData,
        getUniqueValues,
        getStats,
    };
})();
