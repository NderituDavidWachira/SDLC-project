"""Matplotlib charts rendered server-side to base64 PNG (no pyplot global state)."""
import base64
import io

from matplotlib.figure import Figure

COLORS = {'Critical': '#B42318', 'High': '#D9730D', 'Medium': '#C9A227', 'Low': '#3B7A57'}
INK = '#1B2B30'
GRID = '#D7DEE1'
ORDER = ['Critical', 'High', 'Medium', 'Low']


def _encode(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=110, bbox_inches='tight', facecolor='white')
    return base64.b64encode(buf.getvalue()).decode('ascii')


def _empty(ax, msg='Nothing found yet'):
    ax.text(0.5, 0.5, msg, ha='center', va='center', color=INK, transform=ax.transAxes)
    ax.axis('off')


def findings_by_pillar(names, matrix):
    """Stacked horizontal bars: matrix[severity] = list of counts per pillar."""
    fig = Figure(figsize=(6.4, 3.2))
    ax = fig.subplots()
    if not any(sum(v) for v in matrix.values()):
        _empty(ax)
        return _encode(fig)
    left = [0] * len(names)
    for sev in ORDER:
        vals = matrix.get(sev, [0] * len(names))
        ax.barh(names, vals, left=left, color=COLORS[sev], label=sev, height=0.6)
        left = [a + b for a, b in zip(left, vals)]
    ax.invert_yaxis()
    ax.set_xlabel('Open findings', color=INK, fontsize=9)
    ax.legend(frameon=False, fontsize=8, ncol=4, loc='lower center', bbox_to_anchor=(0.5, 1.0))
    ax.xaxis.grid(True, color=GRID, linewidth=0.6)
    ax.set_axisbelow(True)
    for side in ('top', 'right'):
        ax.spines[side].set_visible(False)
    ax.tick_params(colors=INK, labelsize=9)
    return _encode(fig)


def severity_donut(counts):
    fig = Figure(figsize=(3.4, 3.2))
    ax = fig.subplots()
    vals = [counts.get(s, 0) for s in ORDER]
    if not sum(vals):
        _empty(ax)
        return _encode(fig)
    ax.pie(vals, colors=[COLORS[s] for s in ORDER], startangle=90, counterclock=False,
           wedgeprops={'width': 0.38, 'edgecolor': 'white'})
    ax.text(0, 0, str(sum(vals)), ha='center', va='center', fontsize=18,
            fontweight='bold', color=INK)
    ax.legend([f'{s} ({counts.get(s, 0)})' for s in ORDER], frameon=False, fontsize=8,
              loc='upper center', bbox_to_anchor=(0.5, 0.02), ncol=2)
    return _encode(fig)
