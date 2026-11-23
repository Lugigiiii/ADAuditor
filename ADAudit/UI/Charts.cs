using System.Globalization;
using System.Windows;
using System.Windows.Input;
using System.Windows.Media;

namespace ADAudit.UI;

/// <summary>Smooth area chart (one or two series) with gradient fill and hover read-out. Also used as sparkline.</summary>
public sealed class AreaChart : FrameworkElement
{
    double[] _a = Array.Empty<double>(), _b = Array.Empty<double>();
    string[] _labels = Array.Empty<string>();
    int _hover = -1;

    public Color ColorA { get; set; } = (Color)ColorConverter.ConvertFromString("#2DD4BF");
    public Color ColorB { get; set; } = (Color)ColorConverter.ConvertFromString("#8B5CF6");
    public string NameA { get; set; } = "";
    public string NameB { get; set; } = "";
    public bool Sparkline { get; set; }

    public AreaChart()
    {
        MouseMove += (_, e) => { if (!Sparkline) { _hover = IndexAt(e.GetPosition(this).X); InvalidateVisual(); } };
        MouseLeave += (_, _) => { _hover = -1; InvalidateVisual(); };
    }

    public void SetData(double[] a, double[]? b, string[] labels)
    {
        _a = a;
        _b = b ?? Array.Empty<double>();
        _labels = labels;
        InvalidateVisual();
    }

    Rect Plot => Sparkline ? new Rect(0, 4, ActualWidth, Math.Max(1, ActualHeight - 4))
                           : new Rect(36, 10, Math.Max(1, ActualWidth - 46), Math.Max(1, ActualHeight - 34));

    int IndexAt(double x)
    {
        if (_a.Length < 2) return -1;
        var p = Plot;
        return (int)Math.Clamp(Math.Round((x - p.Left) / p.Width * (_a.Length - 1)), 0, _a.Length - 1);
    }

    protected override void OnRender(DrawingContext dc)
    {
        dc.DrawRectangle(Brushes.Transparent, null, new Rect(0, 0, ActualWidth, ActualHeight)); // hit-testable
        if (_a.Length < 2) return;
        var p = Plot;
        double max = Math.Max(1, Math.Max(_a.Max(), _b.Length > 0 ? _b.Max() : 0)) * 1.15;
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;

        if (!Sparkline)
        {
            var grid = new Pen(new SolidColorBrush(Color.FromArgb(0x16, 0xFF, 0xFF, 0xFF)), 1);
            for (int i = 0; i <= 4; i++)
            {
                double y = Math.Round(p.Top + p.Height * i / 4) + 0.5;
                dc.DrawLine(grid, new Point(p.Left, y), new Point(p.Right, y));
                Text(dc, Math.Round(max * (4 - i) / 4).ToString("N0"), new Point(0, y - 8), 10.5, dpi, "#6B7A8C");
            }
            int step = Math.Max(1, _labels.Length / 6);
            for (int i = 0; i < _labels.Length; i += step)
                Text(dc, _labels[i], new Point(X(p, i) - 14, p.Bottom + 6), 10.5, dpi, "#6B7A8C");
        }

        if (_b.Length == _a.Length) Series(dc, p, _b, max, ColorB);
        Series(dc, p, _a, max, ColorA);

        if (_hover >= 0 && !Sparkline)
        {
            double x = X(p, _hover);
            dc.DrawLine(new Pen(new SolidColorBrush(Color.FromArgb(0x50, 0xFF, 0xFF, 0xFF)), 1) { DashStyle = DashStyles.Dash },
                new Point(x, p.Top), new Point(x, p.Bottom));
            double ya = Y(p, _a[_hover], max);
            dc.DrawEllipse(new SolidColorBrush(ColorA), new Pen(Brushes.White, 2), new Point(x, ya), 5, 5);
            var text = $"{_labels[_hover]}\n{NameA}: {_a[_hover]:N0}" + (_b.Length == _a.Length ? $"\n{NameB}: {_b[_hover]:N0}" : "");
            var ft = Fmt(text, 12, dpi, "#FFFFFF");
            double bx = Math.Min(x + 10, p.Right - ft.Width - 16), by = Math.Max(p.Top, ya - ft.Height - 20);
            dc.DrawRoundedRectangle(new SolidColorBrush(Color.FromArgb(0xE6, 0x16, 0x20, 0x33)),
                new Pen(new SolidColorBrush(Color.FromArgb(0x40, 0xFF, 0xFF, 0xFF)), 1), new Rect(bx, by, ft.Width + 16, ft.Height + 10), 8, 8);
            dc.DrawText(ft, new Point(bx + 8, by + 5));
        }
    }

    double X(Rect p, int i) => p.Left + p.Width * i / (_a.Length - 1);
    static double Y(Rect p, double v, double max) => p.Bottom - p.Height * v / max;

    void Series(DrawingContext dc, Rect p, double[] v, double max, Color c)
    {
        var pts = v.Select((val, i) => new Point(X(p, i), Y(p, val, max))).ToArray();
        var line = new StreamGeometry();
        var area = new StreamGeometry();
        using (var g = line.Open()) Smooth(g, pts, false, p);
        using (var g = area.Open()) Smooth(g, pts, true, p);
        line.Freeze(); area.Freeze();
        var fill = new LinearGradientBrush(Color.FromArgb(0x70, c.R, c.G, c.B), Color.FromArgb(0x00, c.R, c.G, c.B), 90);
        dc.DrawGeometry(fill, null, area);
        dc.DrawGeometry(null, new Pen(new SolidColorBrush(c), Sparkline ? 1.6 : 2.2) { LineJoin = PenLineJoin.Round }, line);
    }

    /// <summary>Catmull-Rom spline through the points, as cubic Béziers.</summary>
    static void Smooth(StreamGeometryContext g, Point[] pts, bool closeToBase, Rect p)
    {
        if (closeToBase)
        {
            g.BeginFigure(new Point(pts[0].X, p.Bottom), true, true);
            g.LineTo(pts[0], false, false);
        }
        else g.BeginFigure(pts[0], false, false);
        for (int i = 0; i < pts.Length - 1; i++)
        {
            var p0 = pts[Math.Max(0, i - 1)]; var p1 = pts[i]; var p2 = pts[i + 1]; var p3 = pts[Math.Min(pts.Length - 1, i + 2)];
            var c1 = new Point(p1.X + (p2.X - p0.X) / 6, Math.Min(p.Bottom, p1.Y + (p2.Y - p0.Y) / 6));
            var c2 = new Point(p2.X - (p3.X - p1.X) / 6, Math.Min(p.Bottom, p2.Y - (p3.Y - p1.Y) / 6));
            g.BezierTo(c1, c2, p2, true, true);
        }
        if (closeToBase) g.LineTo(new Point(pts[^1].X, p.Bottom), false, false);
    }

    static FormattedText Fmt(string s, double size, double dpi, string color) =>
        new(s, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), size,
            new SolidColorBrush((Color)ColorConverter.ConvertFromString(color)), dpi);

    static void Text(DrawingContext dc, string s, Point at, double size, double dpi, string color) => dc.DrawText(Fmt(s, size, dpi, color), at);
}

/// <summary>Donut chart with the total in the middle.</summary>
public sealed class DonutChart : FrameworkElement
{
    (double value, Color color)[] _slices = Array.Empty<(double, Color)>();
    string _center = "", _sub = "";

    public void SetData(IEnumerable<(double value, Color color)> slices, string center, string sub)
    {
        _slices = slices.Where(s => s.value > 0).ToArray();
        _center = center;
        _sub = sub;
        InvalidateVisual();
    }

    protected override void OnRender(DrawingContext dc)
    {
        double size = Math.Min(ActualWidth, ActualHeight);
        if (size < 20) return;
        var c = new Point(ActualWidth / 2, ActualHeight / 2);
        double r = size / 2 - 10, thick = Math.Max(10, size * 0.11);
        double dpi = VisualTreeHelper.GetDpi(this).PixelsPerDip;
        dc.DrawEllipse(null, new Pen(new SolidColorBrush(Color.FromArgb(0x18, 0xFF, 0xFF, 0xFF)), thick), c, r, r);

        double total = _slices.Sum(s => s.value), a0 = -90;
        foreach (var (v, col) in _slices)
        {
            double sweep = 360 * v / total;
            if (sweep >= 359.9) { dc.DrawEllipse(null, new Pen(new SolidColorBrush(col), thick), c, r, r); break; }
            var gap = _slices.Length > 1 ? Math.Min(2.5, sweep / 3) : 0;
            Arc(dc, c, r, a0 + gap / 2, sweep - gap, new Pen(new SolidColorBrush(col), thick) { StartLineCap = PenLineCap.Round, EndLineCap = PenLineCap.Round });
            a0 += sweep;
        }

        var big = new FormattedText(_center, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface(new FontFamily("Segoe UI"), FontStyles.Normal, FontWeights.SemiBold, FontStretches.Normal),
            size * 0.16, Brushes.White, dpi);
        var small = new FormattedText(_sub, CultureInfo.CurrentCulture, FlowDirection.LeftToRight, new Typeface("Segoe UI"), Math.Max(10, size * 0.065),
            new SolidColorBrush((Color)ColorConverter.ConvertFromString("#8FA3B8")), dpi);
        dc.DrawText(big, new Point(c.X - big.Width / 2, c.Y - big.Height / 2 - small.Height / 2));
        dc.DrawText(small, new Point(c.X - small.Width / 2, c.Y + big.Height / 2 - small.Height / 2));
    }

    static void Arc(DrawingContext dc, Point c, double r, double startDeg, double sweepDeg, Pen pen)
    {
        Point P(double deg) => new(c.X + r * Math.Cos(deg * Math.PI / 180), c.Y + r * Math.Sin(deg * Math.PI / 180));
        var g = new StreamGeometry();
        using (var ctx = g.Open())
        {
            ctx.BeginFigure(P(startDeg), false, false);
            ctx.ArcTo(P(startDeg + sweepDeg), new Size(r, r), 0, sweepDeg > 180, SweepDirection.Clockwise, true, false);
        }
        g.Freeze();
        dc.DrawGeometry(null, pen, g);
    }
}
